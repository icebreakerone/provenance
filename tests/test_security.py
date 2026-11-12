"""Verification checks added for security (plan section 1)."""

import base64
import datetime
from unittest.mock import patch

import pytest

from ib1.provenance import (
    CertificateNotFoundError,
    Record,
    ValidationError,
    VerificationError,
)
from ib1.provenance.certificates import (
    CertificatesProviderLocal,
)
from ib1.provenance.signing import SignerInMemory
from pki import SCHEME_URL, TRUST_FRAMEWORK_URL
from test_record import edp_record, verify


@pytest.fixture
def signed(edp, self_contained_provider):
    record, ids = edp_record(edp, self_contained_provider)
    return record.encoded(), ids


def signature_block(encoded):
    return encoded["steps"][-1]


# --- 1.1 The signing certificate must match the serial in the signature ----


class SignerClaimingSerial(SignerInMemory):
    def __init__(self, claimed_serial, *args):
        super().__init__(*args)
        self._claimed_serial = claimed_serial

    def serial(self):
        return self._claimed_serial


def test_certificate_serial_must_match_signature(edp, cap, self_contained_provider):
    # CAP signs naming the EDP's serial, and maps that serial to its own certificate
    signer = SignerClaimingSerial(
        str(edp.serial), self_contained_provider, cap.bundle, cap.key
    )
    record = Record(TRUST_FRAMEWORK_URL)
    record.add_step({"type": "origin", "scheme": SCHEME_URL})
    encoded = record.sign(signer).encoded()
    assert encoded["certificates"][str(edp.serial)][0].startswith("-----BEGIN")
    with pytest.raises(VerificationError, match="serial number"):
        verify(encoded, self_contained_provider)


def test_missing_issuer_certificate(signed, pki, self_contained_provider):
    encoded, _ = signed
    del encoded["certificates"][str(pki.issuer.serial_number)]
    with pytest.raises(CertificateNotFoundError, match="Issuer"):
        verify(encoded, self_contained_provider)


def test_missing_local_bundle(edp, pki, tmp_path, local_provider):
    record, _ = edp_record(edp, local_provider)
    empty = CertificatesProviderLocal(pki.root_pem, str(tmp_path / "empty"))
    with pytest.raises(CertificateNotFoundError):
        verify(record.encoded(), empty)


# --- 1.2 Signature element shape --------------------------------------------


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda b: b.pop(), "4 items"),
        (lambda b: b.append("extra"), "4 items"),
        (lambda b: b.__setitem__(0, "0"), "version must be a number"),
        (lambda b: b.__setitem__(0, False), "version must be a number"),
        (lambda b: b.__setitem__(1, 123456), "serial"),
        (lambda b: b.__setitem__(1, "-123456"), "serial"),
        (lambda b: b.__setitem__(1, "0123456"), "serial"),
        (lambda b: b.__setitem__(2, "2024-09-16 15:40:00"), "timestamp"),
        (lambda b: b.__setitem__(2, "2024-09-16T15:40:00+00:00"), "timestamp"),
        (lambda b: b.__setitem__(2, None), "timestamp"),
        (lambda b: b.__setitem__(3, None), "Signature must be a string"),
        (lambda b: b.__setitem__(3, "not base64!"), "base64url"),
    ],
)
def test_bad_signature_element(signed, self_contained_provider, change, message):
    encoded, _ = signed
    change(signature_block(encoded))
    with pytest.raises(VerificationError, match=message):
        verify(encoded, self_contained_provider)


def test_signature_element_must_be_list(signed, self_contained_provider):
    encoded, _ = signed
    encoded["steps"][-1] = "not a signature"
    with pytest.raises(VerificationError, match="signature element"):
        verify(encoded, self_contained_provider)


def test_step_list_needs_a_step(signed, self_contained_provider):
    encoded, _ = signed
    encoded["steps"] = encoded["steps"][-1:]
    with pytest.raises(VerificationError, match="at least one element"):
        verify(encoded, self_contained_provider)


def test_step_list_elements_must_be_steps_or_lists(signed, self_contained_provider):
    encoded, _ = signed
    encoded["steps"][0] = {"type": "origin"}
    with pytest.raises(VerificationError, match="only contain"):
        verify(encoded, self_contained_provider)


def test_signature_without_padding_verifies(signed, self_contained_provider):
    encoded, _ = signed
    signature_block(encoded)[3] = signature_block(encoded)[3].rstrip("=")
    verify(encoded, self_contained_provider)


def sign_raw(data, member, provider, certificates):
    """Sign a hand-built step list, to test input other libraries might produce."""
    serial = str(member.serial)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    signature_data = Record(TRUST_FRAMEWORK_URL)._data_for_signing(
        data, ["0", serial, timestamp]
    )
    signature = member.signer(provider).sign(signature_data.encode("utf-8"))
    return {
        "ib1:provenance": TRUST_FRAMEWORK_URL,
        "origins": [],
        "steps": data
        + [[0, serial, timestamp, base64.urlsafe_b64encode(signature).decode()]],
        "certificates": certificates,
    }


@pytest.mark.parametrize(
    "step, message",
    [
        (base64.urlsafe_b64encode(b"not json").decode(), "not encoded JSON"),
        (base64.urlsafe_b64encode(b"[1, 2]").decode(), "not a JSON object"),
        ("not base64!", "base64url"),
    ],
)
def test_step_that_is_not_a_json_object(
    signed, edp, self_contained_provider, step, message
):
    encoded, _ = signed
    raw = sign_raw([step], edp, self_contained_provider, encoded["certificates"])
    with pytest.raises(VerificationError, match=message):
        verify(raw, self_contained_provider)


# --- 1.3 Top level properties -----------------------------------------------


def test_unknown_top_level_property(signed, edp, cap, self_contained_provider):
    # Top level properties are not signed, so the record still verifies and can
    # be passed on. validate() reports them, and signing again drops them.
    encoded, ids = signed
    encoded["perseus:extra"] = {"anything": True}
    record = verify(encoded, self_contained_provider)
    assert record.validate() == [
        "Provenance record has unknown top level properties: perseus:extra"
    ]
    record.add_step({"type": "receipt", "transfer": ids["transfer"]})
    resigned = record.sign(cap.signer(self_contained_provider)).encoded()
    assert "perseus:extra" not in resigned
    assert verify(resigned, self_contained_provider).validate() == []


def test_origins_must_be_a_list(signed):
    encoded, _ = signed
    encoded["origins"] = "4cN6b85eT7F5MCTTxhiI"
    with pytest.raises(ValidationError, match="origins"):
        Record(TRUST_FRAMEWORK_URL, encoded)


def test_certificates_must_be_a_map(signed):
    encoded, _ = signed
    encoded["certificates"] = []
    with pytest.raises(ValidationError, match="certificates"):
        Record(TRUST_FRAMEWORK_URL, encoded)


def test_record_must_be_a_dict():
    with pytest.raises(ValidationError):
        Record(TRUST_FRAMEWORK_URL, [])


# --- 1.4 Duplicate step ids ---------------------------------------------------


def test_adding_the_same_record_twice_fails_at_signing(
    edp, cap, self_contained_provider
):
    record, _ = edp_record(edp, self_contained_provider)
    merged = Record(TRUST_FRAMEWORK_URL)
    merged.add_record(record)
    merged.add_record(record)
    with pytest.raises(ValidationError, match="more than once"):
        merged.sign(cap.signer(self_contained_provider))


def test_duplicate_ids_fail_verification(edp, cap, self_contained_provider):
    record, _ = edp_record(edp, self_contained_provider)
    merged = Record(TRUST_FRAMEWORK_URL)
    merged.add_record(record)
    merged.add_record(record)
    # Bypass the signing check to produce a record another library might create
    with patch.object(Record, "_duplicate_ids", return_value=[]):
        encoded = merged.sign(cap.signer(self_contained_provider)).encoded()
    with pytest.raises(VerificationError, match="more than once"):
        verify(encoded, self_contained_provider)


# --- 1.6 Checking who signed a step -------------------------------------------


@pytest.fixture
def verified(signed, self_contained_provider):
    encoded, ids = signed
    return verify(encoded, self_contained_provider), ids


def test_require_signer_passes(verified, edp):
    record, ids = verified
    step = record.require_signer(
        ids["transfer"],
        member=edp.member,
        application=edp.application,
        role=edp.roles[0],
    )
    assert step["type"] == "transfer"


def test_require_signer_wrong_role(verified, cap):
    record, ids = verified
    with pytest.raises(VerificationError, match="does not have role"):
        record.require_signer(ids["transfer"], role=cap.roles[0])


def test_require_signer_wrong_member(verified, cap):
    record, ids = verified
    with pytest.raises(VerificationError, match="expected " + cap.member):
        record.require_signer(ids["transfer"], member=cap.member)


def test_require_signer_needs_verified_record(signed):
    encoded, ids = signed
    with pytest.raises(Exception, match="not verified"):
        Record(TRUST_FRAMEWORK_URL, encoded).require_signer(ids["transfer"])
