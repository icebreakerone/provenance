import json

from cryptography import x509

from icebreakerone.provenance import Record
from icebreakerone.provenance.signing import SignerLocal
from icebreakerone.provenance.certificates import CertificatesLocal

if __name__ == "__main__":
    signer1 = SignerLocal("certs/123456-bundle.pem", "certs/6-application-one-key.pem")
    signer2 = SignerLocal("certs/98765-bundle.pem", "certs/7-application-two-key.pem")
    # signer2 = SignerLocal("certs/123456-bundle.pem", "certs/7-application-two-key.pem") # test invalid cert
    certificates = CertificatesLocal("certs")

    record = Record()
    record.add_step({"abc":1})
    record.add_step({"hello":2})
    record2 = record.sign(signer1)
    # print(record2.encoded())
    record2.verify(certificates)
    print(json.dumps(record2.encoded(), indent=2).encode("utf-8").decode('utf-8'))

    record2.add_step({"test2":"seventeen"})
    record3 = record2.sign(signer2)
    record3.verify(certificates)
    print(json.dumps(record3.encoded(), indent=2).encode("utf-8").decode('utf-8'))
