import json

from cryptography import x509

from icebreakerone.provenance import Record
from icebreakerone.provenance.signing import SignerLocal
from icebreakerone.provenance.certificates import CertificatesLocal

if __name__ == "__main__":
    # Create two signers representing two applications to illustrate a record
    # passed between two members. (In a real application, you'd only have one.)
    # A few signer classes should be provided, eg local PEM files like this one,
    # or a key stored in AWS' key service.
    signer1 = SignerLocal("certs/123456-bundle.pem", "certs/6-application-one-key.pem")
    signer2 = SignerLocal("certs/98765-bundle.pem", "certs/7-application-two-key.pem")
    # signer2 = SignerLocal("certs/123456-bundle.pem", "certs/7-application-two-key.pem") # test invalid cert
    # Create a mechanism to provide certificates for verification. Again, multiple
    # implementations, entirely local, fetch from Directory with local caching, etc.
    # This also provides the signing CA root certificate, which could just be included
    # in the application code.
    certificates = CertificatesLocal("certs", "certs/4-signing-ca-cert.pem")

    # Create a record and add two steps
    record = Record()
    record.add_step({
        "id": "URd0wgs",
        "type": "transfer",
        "from": "https://directory.estf.ib1.org/member/28761",
        "source": {
            "endpoint": "https://api65.example.com/energy",
            "parameters": {
                "from": "2024-09-16T00:00:00Z",
                "to": "2024-09-16T12:00:00Z"
            },
            "permission": {
                "encoded": "permission record"
            }
        },
        "timestamp": "2024-09-16T15:32:56Z"        # in the past, signing is independent of times in steps
    })
    record.add_step({
        "id": "itINsGtU",
        "type": "receipt",
        "from": "https://directory.estf.ib1.org/member/237346",
        "of": "URd0wgs"
    })
    # Then sign it, returning a new Record object
    record2 = record.sign(signer1)
    # print(record2.encoded())

    # Verify the record using the certificates
    record2.verify(certificates)
    # Print the encoded form -- this is how it will be transported
    print("----- First record -----")
    print(json.dumps(record2.encoded(), indent=2).encode("utf-8").decode('utf-8'))

    # Add more steps to this, and sign it, then verify the new version
    record2.add_step({
        "id": "wbgoUD",
        "type": "process",
        "process": "https://directory.estf.ib1.org/scheme/electricity/process/emissions-report",
        "of": "itINsGtU"
    })
    record3 = record2.sign(signer2)
    record3.verify(certificates)

    # Print records
    print("----- Second record, including first record -----")
    print(json.dumps(record3.encoded(), indent=2).encode("utf-8").decode('utf-8'))
    print("----- Decoded form of record including signature information -----")
    print(json.dumps(record3.decoded(), indent=2).encode("utf-8").decode('utf-8'))
