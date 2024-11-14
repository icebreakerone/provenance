import json

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ib1.provenance import Record
from ib1.provenance.signing import SignerFiles, SignerInMemory
from ib1.provenance.certificates import (
    CertificatesProviderSelfContainedRecord,
    CertificatesProviderLocal,
)


TRUST_FRAMEWORK_URL = "https://registry.core.trust.ib1.org/trust-framework"


def create_provenance_records(self_contained):
    # Create a mechanism to provide certificates for verification. Multiple
    # implementations: embed certificates in record, entirely local, fetch from
    # Directory with local caching, etc.
    # Implements certificate policy, including whether certificates are included
    # in the record.
    # Provides the signing CA root certificate. Each environment will have its own
    # root CA.
    if self_contained:
        # Use certificates from the record, with policy to include them when adding steps
        certificate_provider = CertificatesProviderSelfContainedRecord(
            "certs/4-signing-ca-cert.pem"
        )
    else:
        # Use certificates contained in a local directory, don't include certs in record
        certificate_provider = CertificatesProviderLocal(
            "certs/4-signing-ca-cert.pem", "certs"
        )

    # Create two signers representing two applications to illustrate a record
    # passed between two members. (In a real application, you'd only have one.)
    # A few signer classes should be provided, eg local PEM files like this one,
    # or a key stored in AWS' key service.
    # Uses a Certificate Provider object for access to certificate policy.
    # Energy Data Provider Signer with certificates and key stored in files:
    signer_edp = SignerFiles(
        certificate_provider,
        "certs/123456-bundle.pem",
        "certs/6-honest-daves-accurate-meter-readings-key.pem",
    )
    # Carbon Accounting Platform Signer using in-memory Python objects:
    with open("certs/98765-bundle.pem", "rb") as certs:
        signer_cap_certs = x509.load_pem_x509_certificates(certs.read())
    with open("certs/7-emission-calculations-4-u-key.pem", "rb") as key:
        signer_cap_key = serialization.load_pem_private_key(key.read(), password=None)
    signer_cap = SignerInMemory(
        certificate_provider,
        signer_cap_certs,  # list containing certificate and issuer chain
        signer_cap_key     # private key
    )
    # signer_cap = SignerLocal(certificate_provider, "certs/123456-bundle.pem", "certs/7-application-two-key.pem") # test invalid cert
    # Bank Signer
    signer_bank = SignerFiles(
        certificate_provider,
        "certs/88889999-bundle.pem",
        "certs/8-green-bank-of-london-key.pem",
    )

    # Create a record and add two steps
    record = Record(TRUST_FRAMEWORK_URL)
    origin_id = record.add_step(
        {
            "type": "origin"
        }
    )
    transfer_id = record.add_step(
        {
            "type": "transfer",
            "from": "https://directory.core.trust.ib1.org/member/28761",
            "source": {
                "endpoint": "https://api65.example.com/energy",
                "parameters": {
                    "from": "2024-09-16T00:00:00Z",
                    "to": "2024-09-16T12:00:00Z",
                },
                "permission": {"encoded": "permission record"},
            },
            "timestamp": "2024-09-16T15:32:56Z",  # in the past, signing is independent of times in steps
        }
    )
    record.add_step(
        {
            "type": "receipt",
            "from": "https://directory.core.trust.ib1.org/member/237346",
            "transfer": transfer_id,
        }
    )
    # Add steps from another record
    record_for_adding = Record(TRUST_FRAMEWORK_URL)
    record_for_adding.add_step({"type":"origin"})
    record_for_adding.add_step(
        {
            "type": "transfer",
            "from": "https://directory.core.trust.ib1.org/member/3456643",
            "source": {
                "endpoint": "https://e1.example.org/emission",
            },
        }
    )
    record.add_record(record_for_adding.sign(signer_cap))
    # Then sign it, returning a new Record object
    record2_generated = record.sign(signer_edp)
    record2 = Record(TRUST_FRAMEWORK_URL, record2_generated.encoded())  # create a new Record from the encoded structure
    # print(record2.encoded())

    # Verify the record using the certificates
    record2.verify(certificate_provider)
    # Print the encoded form -- this is how it will be transported
    print("----- First record -----")
    print(json.dumps(record2.encoded(), indent=2).encode("utf-8").decode("utf-8"))

    # Add more steps to this, and sign it, then verify the new version
    record2.add_step(
        {
            "type": "process",
            "process": "https://directory.core.trust.ib1.org/scheme/perseus/process/emissions-report",
            "of": "itINsGtU",
        }
    )
    record3 = record2.sign(signer_bank)
    record3.verify(certificate_provider)

    # Print records
    print("----- Second record, including first record -----")
    print(json.dumps(record3.encoded(), indent=2).encode("utf-8").decode("utf-8"))
    print("----- Decoded form of record including signature information -----")
    print(json.dumps(record3.decoded(), indent=2).encode("utf-8").decode("utf-8"))


if __name__ == "__main__":
    # Self-contained, with certificates encoded
    create_provenance_records(True)
    # Without certificates, for much smaller records
    create_provenance_records(False)
