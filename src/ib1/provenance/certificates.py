import datetime
import re

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import asn1crypto.core as asn1

from .exceptions import CertificateError, CertificateNotFoundError, VerificationError

# ---------------------------------------------------------------------------

OID_IB1_ROLES = x509.ObjectIdentifier("1.3.6.1.4.1.62329.1.1")
OID_IB1_MEMBER = x509.ObjectIdentifier("1.3.6.1.4.1.62329.1.3")

SERIAL_PATTERN = re.compile(r"^(0|[1-9][0-9]*)$")


class CertExtUTF8Sequence(asn1.SequenceOf):
    _child_spec = asn1.UTF8String


class SigningCertificate:
    def __init__(self, x509_certificate: x509.Certificate):
        self._x509_certificate = x509_certificate

    def application(self):
        san_extension = self._x509_certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        uri = san_extension.value.get_values_for_type(x509.UniformResourceIdentifier)
        if len(uri) != 1:
            raise CertificateError(
                "Certificate doesn't contain exactly one URI subject alternative name"
            )
        return uri[0]

    def organisation_name(self):
        return self._x509_certificate.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )[0].value

    def member(self):
        value = self._x509_certificate.extensions.get_extension_for_oid(
            OID_IB1_MEMBER
        ).value.value  # type: ignore [attr-defined]
        return str(asn1.UTF8String.load(value))

    def roles(self):
        value = self._x509_certificate.extensions.get_extension_for_oid(
            OID_IB1_ROLES
        ).value.value  # type: ignore [attr-defined]
        return list(map(str, CertExtUTF8Sequence.load(value)))


class CertificateProviderBase:
    def __init__(self, root_ca_certificate: bytes, self_contained=False):
        self.policy_include_certificates_in_record = self_contained
        self._ca_store = Store(x509.load_pem_x509_certificates(root_ca_certificate))

    def verify(self, certificates_from_record, serial, sign_timestamp, data, signature):
        if not isinstance(serial, str) or not SERIAL_PATTERN.match(serial):
            raise VerificationError(
                f"Bad certificate serial number in record: {serial!r}"
            )
        certs = self.certificates_for_serial(certificates_from_record, serial)
        # first certificate in file is signing certificate
        signing_cert, *issuer_chain = certs
        # 1) the certificate must be the one the signature names
        if str(signing_cert.serial_number) != serial:
            raise VerificationError(
                f"Signing certificate has serial number {signing_cert.serial_number}, "
                f"but the signature names {serial}"
            )
        # 2) check certificate chain validity at the time of signature
        verification_time = datetime.datetime.fromisoformat(sign_timestamp)
        verifier = (
            PolicyBuilder()
            .store(self._ca_store)
            .time(verification_time)
            .build_client_verifier()
        )
        # Revocation is not checked: the Directory does not publish CRLs yet,
        # see https://github.com/icebreakerone/directory/issues/272
        verifier.verify(signing_cert, issuer_chain)
        # 3) check signature on data
        pubkey = signing_cert.public_key()
        pubkey.verify(signature, data, ec.ECDSA(hashes.SHA256()))  # type: ignore [call-arg, union-attr]
        # Return information about the signer
        cert_info = SigningCertificate(signing_cert)
        return {
            "member": cert_info.member(),
            "name": cert_info.organisation_name(),
            "application": cert_info.application(),
            "roles": cert_info.roles(),
        }


class CertificatesProviderLocal(CertificateProviderBase):
    def __init__(self, root_ca_certificate, directory):
        CertificateProviderBase.__init__(self, root_ca_certificate)
        self._directory = directory

    def certificates_for_serial(self, certificates_from_record, serial):
        certificate_filename = self._directory + "/" + str(int(serial)) + "-bundle.pem"
        try:
            with open(certificate_filename, "rb") as f:
                return x509.load_pem_x509_certificates(f.read())
        except FileNotFoundError:
            raise CertificateNotFoundError(
                f"Certificate serial {serial} is not in {self._directory}"
            ) from None


class CertificatesProviderSelfContainedRecord(CertificateProviderBase):
    def __init__(self, root_ca_certificate: bytes):
        super().__init__(root_ca_certificate, self_contained=True)

    def certificates_for_serial(
        self, certificates_from_record: dict, serial: str
    ) -> list:
        certs = certificates_from_record.get(serial)
        if certs is None:
            raise CertificateNotFoundError(
                "Certificate serial " + serial + " is not present in record"
            )
        signing_cert, *path_serials = certs
        cert_chain = [signing_cert]
        for issuer_serial in path_serials:
            if issuer_serial not in certificates_from_record:
                raise CertificateNotFoundError(
                    f"Issuer certificate serial {issuer_serial} is not present in record"
                )
            cert_chain.append(certificates_from_record[issuer_serial][0])
        return list(
            map(lambda c: x509.load_pem_x509_certificate(c.encode("utf-8")), cert_chain)
        )
