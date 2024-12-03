import sys, os, json

from ib1.provenance import Record
from ib1.provenance.certificates import CertificatesProviderSelfContainedRecord

if __name__ == "__main__":
    if len(sys.argv) < 2 or not os.path.exists(sys.argv[1]):
        raise Exception("First command line argument must be the filename of a PEM encoded root signing CA certificate.")
    root_certificate = sys.argv[1]
    certificate_provider = CertificatesProviderSelfContainedRecord(root_certificate)

    record_encoded = json.loads(sys.stdin.read())
    # NOTE: When processing provenance records, always specify the Trust Framework expected.
    # This usage is only permissible because it is a general purpose record decoder.
    record = Record(record_encoded["ib1:provenance"], record_encoded)
    record.verify(certificate_provider)
    print(json.dumps(record.decoded(), indent=2).encode("utf-8").decode("utf-8"))
