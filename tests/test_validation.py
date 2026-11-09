"""Structural checks on steps (plan section 2).

The checks apply when steps are added and signed. Record.verify() does not apply
them, so records signed before they existed still verify.
"""

import json
import pathlib
from unittest.mock import patch

import pytest

from ib1.provenance import ProvenanceError, Record, ValidationError
from ib1.provenance.certificates import CertificatesProviderSelfContainedRecord
from pki import SCHEME_URL, TRUST_FRAMEWORK_URL
from test_record import cap_record, edp_record, verify

VECTORS = pathlib.Path(__file__).parent / "vectors"


def new_record():
    return Record(TRUST_FRAMEWORK_URL)


# --- add_step -----------------------------------------------------------------


def test_unknown_type():
    with pytest.raises(ValidationError, match="type must be one of"):
        new_record().add_step({"type": "transformation"})


def test_missing_type():
    with pytest.raises(ValidationError, match="type must be one of"):
        new_record().add_step({"scheme": SCHEME_URL})


@pytest.mark.parametrize(
    "timestamp",
    [
        # Produced by isoformat()[0:-7] + "Z" in provenance-service and
        # perseus-demo-energy, for times with a time zone or no microseconds
        "2024-09-16T15:32:5Z",
        "2024-09-16T1Z",
        "2024-09-16T15:32:56+00:00",
        "2024-09-16T15:32:56",
        "2024-09-16 15:32:56Z",
        "2025-09-01-T12:34:56Z",
        "2024-13-01T00:00:00Z",
        "2024-09-16",
        1726500776,
    ],
)
def test_bad_timestamp(timestamp):
    with pytest.raises(ValidationError, match="timestamp"):
        new_record().add_step({"type": "origin", "timestamp": timestamp})


@pytest.mark.parametrize(
    "timestamp", ["2024-09-16T15:32:56Z", "2024-09-16T15:32:56.123456Z"]
)
def test_good_timestamp(timestamp):
    new_record().add_step({"type": "origin", "timestamp": timestamp})


def test_bad_expires():
    with pytest.raises(ValidationError, match="expires"):
        new_record().add_step(
            {"type": "permission", "expires": "2025-09-16T15:32:56+00:00"}
        )


def test_expires_only_checked_on_permissions():
    # Other step types don't define expires, so a Scheme may use it differently
    new_record().add_step({"type": "origin", "expires": "next year"})


@pytest.mark.parametrize(
    "step, message",
    [
        ({"type": "transfer", "of": ["a"]}, "of must be a step id"),
        ({"type": "receipt", "transfer": 1}, "transfer must be a step id"),
        ({"type": "process", "inputs": "a"}, "inputs must be a list"),
        ({"type": "origin", "permissions": [1]}, "permissions must be a list"),
    ],
)
def test_reference_shape(step, message):
    with pytest.raises(ValidationError, match=message):
        new_record().add_step(step)


def test_problems_are_reported_together():
    with pytest.raises(ValidationError) as error:
        new_record().add_step({"type": "nope", "timestamp": "yesterday"})
    assert "type" in str(error.value) and "timestamp" in str(error.value)


# --- sign ---------------------------------------------------------------------


def test_record_needs_an_origin(edp, self_contained_provider):
    record = new_record()
    record.add_step({"type": "permission"})
    with pytest.raises(ValidationError, match="at least one origin"):
        record.sign(edp.signer(self_contained_provider))


def test_reference_to_missing_step(edp, self_contained_provider):
    record = new_record()
    record.add_step({"type": "origin"})
    record.add_step({"type": "transfer", "of": "NotInThisRecord1234"})
    with pytest.raises(ValidationError, match="not in this record"):
        record.sign(edp.signer(self_contained_provider))


@pytest.mark.parametrize(
    "make_step, message",
    [
        (lambda ids: {"type": "transfer", "of": ids["permission"]}, "of must refer"),
        (
            lambda ids: {"type": "receipt", "transfer": ids["origin"]},
            "transfer must refer to transfer steps",
        ),
        (
            lambda ids: {"type": "process", "inputs": [ids["transfer"]]},
            "inputs must refer",
        ),
        (
            lambda ids: {"type": "process", "permissions": [ids["origin"]]},
            "permissions must refer to permission steps",
        ),
    ],
)
def test_reference_to_wrong_type(edp, cap, self_contained_provider, make_step, message):
    signed, ids = edp_record(edp, self_contained_provider)
    record = Record(TRUST_FRAMEWORK_URL, signed.encoded())
    record.add_step(make_step(ids))
    with pytest.raises(ValidationError, match=message):
        record.sign(cap.signer(self_contained_provider))


def test_references_into_included_records(edp, cap, self_contained_provider):
    # The receipt refers to the transfer signed by the EDP
    signed, ids = edp_record(edp, self_contained_provider)
    cap_signed, _ = cap_record(cap, self_contained_provider, signed, ids["transfer"])
    assert verify(cap_signed.encoded(), self_contained_provider).validate() == []


def edp_record_with_bad_timestamp(edp, provider):
    """A record like those signed before these checks existed."""
    with patch("ib1.provenance.validation.step_problems", return_value=[]):
        record = new_record()
        origin_id = record.add_step(
            {"type": "origin", "scheme": SCHEME_URL, "timestamp": "2024-09-16T1Z"}
        )
        transfer_id = record.add_step(
            {"type": "transfer", "of": origin_id, "timestamp": "2024-09-16T15:32:5Z"}
        )
        return record.sign(edp.signer(provider)), transfer_id


def test_problems_in_included_records_do_not_block_signing(
    edp, cap, self_contained_provider
):
    signed, transfer_id = edp_record_with_bad_timestamp(edp, self_contained_provider)
    record = Record(TRUST_FRAMEWORK_URL, signed.encoded())
    record.add_step({"type": "receipt", "transfer": transfer_id})
    record.sign(cap.signer(self_contained_provider))


def test_checks_run_before_the_signer_is_called(edp, self_contained_provider):
    record = new_record()
    record.add_step({"type": "permission"})
    signer = edp.signer(self_contained_provider)
    with patch.object(signer, "sign") as sign:
        with pytest.raises(ValidationError):
            record.sign(signer)
    sign.assert_not_called()


# --- verify and validate --------------------------------------------------------


def test_verify_does_not_apply_the_checks(edp, self_contained_provider):
    signed, _ = edp_record_with_bad_timestamp(edp, self_contained_provider)
    record = verify(signed.encoded(), self_contained_provider)
    problems = record.validate()
    assert len(problems) == 2
    assert all("timestamp" in p for p in problems)


def test_validate_reports_missing_origin_and_bad_references(
    edp, self_contained_provider
):
    with patch.object(Record, "_check_before_signing"):
        record = new_record()
        record.add_step({"type": "receipt", "transfer": "NotInThisRecord1234"})
        signed = record.sign(edp.signer(self_contained_provider))
    problems = verify(signed.encoded(), self_contained_provider).validate()
    assert any("at least one origin" in p for p in problems)
    assert any("not in this record" in p for p in problems)


def test_validate_good_record(edp, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    assert verify(signed.encoded(), self_contained_provider).validate() == []


def test_validate_test_vector():
    expected = json.loads((VECTORS / "expected.json").read_text())
    provider = CertificatesProviderSelfContainedRecord(
        (VECTORS / "root-ca.pem").read_bytes()
    )
    record = Record(
        expected["trust_framework"], json.loads((VECTORS / "record.json").read_text())
    )
    record.verify(provider)
    assert record.validate() == []


def test_validate_needs_a_verified_record(edp, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    with pytest.raises(ProvenanceError, match="not verified"):
        signed.validate()
