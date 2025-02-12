import os
import json

import pytest
from ib1.provenance import certificates

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def test_certificate_self_contained_record_certificates_for_serial():
    with open(ROOT_DIR + "/fixtures/4-signing-ca-cert.pem", "rb") as f:
        root_ca_certificate = f.read()
    provider = certificates.CertificatesProviderSelfContainedRecord(root_ca_certificate)
    assert provider.policy_include_certificates_in_record is True
    with open(ROOT_DIR + "/fixtures/certificates_from_record.json", "r") as f:
        certificates_from_record = json.load(f)
    result = provider.certificates_for_serial(
        certificates_from_record=certificates_from_record, serial="123456"
    )
    assert all(isinstance(cert, certificates.x509.Certificate) for cert in result)


def test_certificate_self_contained_record_certificates_for_serial_bad_serial():
    with open(ROOT_DIR + "/fixtures/4-signing-ca-cert.pem", "rb") as f:
        root_ca_certificate = f.read()
    provider = certificates.CertificatesProviderSelfContainedRecord(root_ca_certificate)
    with open(ROOT_DIR + "/fixtures/certificates_from_record.json", "r") as f:
        certificates_from_record = json.load(f)
    with pytest.raises(KeyError):
        provider.certificates_for_serial(
            certificates_from_record=certificates_from_record, serial="1"
        )
