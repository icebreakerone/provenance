"""Test PKI shaped like the Directory's signing certificates (see scripts/certmaker.sh).

Certificates are generated in memory, so tests don't depend on files that expire.
"""

import datetime
from dataclasses import dataclass, field

import asn1crypto.core as asn1
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ib1.provenance.certificates import (
    OID_IB1_MEMBER,
    OID_IB1_ROLES,
    CertExtUTF8Sequence,
)
from ib1.provenance.signing import SignerInMemory

TRUST_FRAMEWORK_URL = "https://registry.core.trust.ib1.org/trust-framework"
SCHEME_URL = "https://registry.core.trust.ib1.org/scheme/perseus"
DIRECTORY = "https://directory.core.trust.ib1.org"


def _name(organisation, common_name):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _key_ids(builder, public_key, issuer_public_key):
    return builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key),
        critical=False,
    )


def _ca_key_usage():
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


@dataclass
class Member:
    """A member application with a signing certificate."""

    name: str
    member: str
    application: str
    roles: list
    serial: int
    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate
    bundle: list = field(default_factory=list)  # [leaf, issuer]

    def signer(self, certificate_provider):
        return SignerInMemory(certificate_provider, self.bundle, self.key)


class PKI:
    """Root CA -> Signing Issuer -> member signing certificates."""

    def __init__(self, not_before=None, not_after=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        self.not_before = not_before or (now - datetime.timedelta(days=1))
        self.not_after = not_after or (now + datetime.timedelta(days=365))

        self.root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = _name("Core Trust Framework", "Core Trust Framework Signing CA")
        builder = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(self.root_key.public_key())
            .serial_number(1000)
            .not_valid_before(self.not_before)
            .not_valid_after(self.not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(_ca_key_usage(), True)
        )
        builder = _key_ids(
            builder, self.root_key.public_key(), self.root_key.public_key()
        )
        self.root = builder.sign(self.root_key, hashes.SHA256())

        self.issuer_key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                _name("Core Trust Framework", "Core Trust Framework Signing Issuer")
            )
            .issuer_name(root_name)
            .public_key(self.issuer_key.public_key())
            .serial_number(2000)
            .not_valid_before(self.not_before)
            .not_valid_after(self.not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(_ca_key_usage(), True)
        )
        builder = _key_ids(
            builder, self.issuer_key.public_key(), self.root_key.public_key()
        )
        self.issuer = builder.sign(self.root_key, hashes.SHA256())

    @property
    def root_pem(self) -> bytes:
        return self.root.public_bytes(serialization.Encoding.PEM)

    def member(self, name, member_id, application_id, roles, serial) -> Member:
        key = ec.generate_private_key(ec.SECP256R1())
        application = f"{DIRECTORY}/application/{application_id}"
        member = f"{DIRECTORY}/member/{member_id}"
        roles_der = CertExtUTF8Sequence([asn1.UTF8String(r) for r in roles]).dump()
        member_der = asn1.UTF8String(member).dump()
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(name, application))
            .issuer_name(self.issuer.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(self.not_before)
            .not_valid_after(self.not_after)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(application)]
                ),
                False,
            )
            .add_extension(x509.UnrecognizedExtension(OID_IB1_ROLES, roles_der), False)
            .add_extension(
                x509.UnrecognizedExtension(OID_IB1_MEMBER, member_der), False
            )
        )
        builder = _key_ids(builder, key.public_key(), self.issuer_key.public_key())
        certificate = builder.sign(self.issuer_key, hashes.SHA256())
        return Member(
            name=name,
            member=member,
            application=application,
            roles=roles,
            serial=serial,
            key=key,
            certificate=certificate,
            bundle=[certificate, self.issuer],
        )

    def write_bundles(self, directory, *members):
        """Write {serial}-bundle.pem files for CertificatesProviderLocal."""
        for m in members:
            pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in m.bundle)
            (directory / f"{m.serial}-bundle.pem").write_bytes(pem)
