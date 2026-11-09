"""Check the library against the fixed vectors in tests/vectors.

Other implementations, such as the TypeScript port, can use the same files: verify
record.json with root-ca.pem, and compare against expected.json.
"""

import base64
import json
import pathlib

import pytest
from cryptography.exceptions import InvalidSignature

from ib1.provenance import Record
from ib1.provenance.certificates import CertificatesProviderSelfContainedRecord

VECTORS = pathlib.Path(__file__).parent / "vectors"


def load(name):
    return json.loads((VECTORS / name).read_text())


@pytest.fixture(scope="module")
def expected():
    return load("expected.json")


@pytest.fixture(scope="module")
def provider():
    return CertificatesProviderSelfContainedRecord(
        (VECTORS / "root-ca.pem").read_bytes()
    )


def test_spec_example_signature_data():
    example = load("spec-example.json")
    record = Record("https://registry.core.trust.ib1.org/trust-framework")
    *data, (version, serial, timestamp, _) = example["steps"]
    assert (
        record._data_for_signing(data, [str(version), serial, timestamp])
        == example["signature_data"]
    )


def test_record_verifies(expected, provider):
    record = Record(expected["trust_framework"], load("record.json"))
    record.verify(provider)
    assert record.decoded() == expected["decoded_steps"]


def test_signature_data(expected):
    encoded = load("record.json")
    record = Record(expected["trust_framework"], encoded)
    for path, container in (
        ("steps", encoded["steps"]),
        ("steps[0]", encoded["steps"][0]),
    ):
        *data, signature = container
        assert (
            record._data_for_signing(data, [str(v) for v in signature[:3]])
            == expected["signature_data"][path]
        )


def test_step_json_encoding(expected):
    # Steps are compact JSON with non-ASCII characters escaped
    origin_encoded = load("record.json")["steps"][0][1]

    raw = base64.urlsafe_b64decode(origin_encoded).decode("ascii")
    assert '"perseus:scheme":{"note":"caf\\u00e9"}' in raw
    assert ", " not in raw and ": " not in raw


def test_tampered_vector_fails(expected, provider):
    encoded = load("record.json")
    encoded["steps"][0][-1][2] = "2024-09-16T15:40:01Z"
    with pytest.raises(InvalidSignature):
        Record(expected["trust_framework"], encoded).verify(provider)
