import base64
import copy
import datetime
import json
import re

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.x509.verification import VerificationError as ChainError

from ib1.provenance import (
    CertificateNotFoundError,
    ProvenanceError,
    Record,
    ValidationError,
    VerificationError,
)
from ib1.provenance.certificates import CertificatesProviderSelfContainedRecord

from pki import PKI, SCHEME_URL, TRUST_FRAMEWORK_URL

ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def decode_step(encoded):
    return json.loads(base64.urlsafe_b64decode(encoded))


def encode_step(step):
    return base64.urlsafe_b64encode(
        json.dumps(step, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8")


def edp_record(edp, provider):
    """EDP adds permission, origin and transfer steps, as in the Perseus guide."""
    record = Record(TRUST_FRAMEWORK_URL)
    permission_id = record.add_step(
        {
            "type": "permission",
            "scheme": SCHEME_URL,
            "account": "account-1",
            "allows": {"licenses": [f"{SCHEME_URL}/license/1"], "processes": []},
            "expires": "2030-01-01T00:00:00Z",
        }
    )
    origin_id = record.add_step(
        {
            "type": "origin",
            "scheme": SCHEME_URL,
            "sourceType": f"{SCHEME_URL}/source-type/Meter",
            "origin": "https://www.smartdcc.co.uk/",
            "external": True,
            "permissions": [permission_id],
        }
    )
    transfer_id = record.add_step(
        {
            "type": "transfer",
            "scheme": SCHEME_URL,
            "of": origin_id,
            "to": "https://directory.core.trust.ib1.org/member/81524",
            "standard": f"{SCHEME_URL}/standard/1",
            "license": f"{SCHEME_URL}/license/1",
            "service": "https://api.example.com/v1/consumption",
            "path": "/readings",
            "parameters": {"measure": "import"},
            "permissions": [permission_id],
        }
    )
    signed = record.sign(edp.signer(provider))
    return signed, {
        "permission": permission_id,
        "origin": origin_id,
        "transfer": transfer_id,
    }


def cap_record(cap, provider, edp_signed, transfer_id):
    """CAP verifies the EDP record, then adds receipt and process steps."""
    record = Record(TRUST_FRAMEWORK_URL, edp_signed.encoded())
    record.verify(provider)
    receipt_id = record.add_step(
        {"type": "receipt", "scheme": SCHEME_URL, "transfer": transfer_id}
    )
    process_id = record.add_step(
        {
            "type": "process",
            "scheme": SCHEME_URL,
            "inputs": [receipt_id],
            "process": f"{SCHEME_URL}/process/emissions-calculation",
        }
    )
    return record.sign(cap.signer(provider)), {
        "receipt": receipt_id,
        "process": process_id,
    }


def verify(encoded, provider):
    record = Record(TRUST_FRAMEWORK_URL, encoded)
    record.verify(provider)
    return record


# --- Signing and verification ----------------------------------------------


def test_sign_then_verify(edp, self_contained_provider):
    signed, ids = edp_record(edp, self_contained_provider)
    record = verify(signed.encoded(), self_contained_provider)
    steps = record.decoded()
    assert [s["type"] for s in steps] == ["permission", "origin", "transfer"]
    assert [s["id"] for s in steps] == [
        ids["permission"],
        ids["origin"],
        ids["transfer"],
    ]
    for step in steps:
        assert step["_signature"]["signed"] == {
            "member": edp.member,
            "name": edp.name,
            "application": edp.application,
            "roles": edp.roles,
        }
        assert step["_signature"]["includedBy"] == []


def test_encoded_structure(edp, self_contained_provider):
    signed, ids = edp_record(edp, self_contained_provider)
    encoded = signed.encoded()
    assert set(encoded) == {"ib1:provenance", "origins", "steps", "certificates"}
    assert encoded["ib1:provenance"] == TRUST_FRAMEWORK_URL
    assert encoded["origins"] == [ids["origin"]]
    *steps, signature = encoded["steps"]
    assert len(steps) == 3
    version, serial, timestamp, sig = signature
    assert version == 0
    assert serial == str(edp.serial)
    assert TIMESTAMP_PATTERN.match(timestamp)
    # DER encoded ECDSA, base64url with padding
    der = base64.urlsafe_b64decode(sig)
    assert der[0] == 0x30 and 68 <= len(der) <= 72


def test_steps_are_padded_base64url_json(edp, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    *steps, _ = signed.encoded()["steps"]
    for encoded in steps:
        assert re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", encoded)
        assert len(encoded) % 4 == 0
        step = decode_step(encoded)
        assert list(step)[:3] == ["id", "timestamp", "type"]


def test_ids_and_timestamps(edp, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    steps = verify(signed.encoded(), self_contained_provider).decoded()
    for step in steps:
        assert ID_PATTERN.match(step["id"])
        assert TIMESTAMP_PATTERN.match(step["timestamp"])
    assert len({s["id"] for s in steps}) == len(steps)


def test_explicit_step_timestamp_is_kept(edp, self_contained_provider):
    record = Record(TRUST_FRAMEWORK_URL)
    record.add_step({"type": "origin", "timestamp": "2024-09-16T15:32:56Z"})
    steps = verify(
        record.sign(edp.signer(self_contained_provider)).encoded(),
        self_contained_provider,
    ).decoded()
    assert steps[0]["timestamp"] == "2024-09-16T15:32:56Z"


def test_self_contained_certificates(pki, edp, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    certificates = signed.encoded()["certificates"]
    issuer_serial = str(pki.issuer.serial_number)
    leaf_pem, *issuer_serials = certificates[str(edp.serial)]
    assert leaf_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert issuer_serials == [issuer_serial]
    assert len(certificates[issuer_serial]) == 1


def test_local_certificate_provider(edp, local_provider):
    signed, _ = edp_record(edp, local_provider)
    assert "certificates" not in signed.encoded()
    steps = verify(signed.encoded(), local_provider).decoded()
    assert len(steps) == 3


def test_add_step_returns_without_mutating_input(edp):
    step = {"type": "origin", "scheme": SCHEME_URL}
    Record(TRUST_FRAMEWORK_URL).add_step(step)
    assert step == {"type": "origin", "scheme": SCHEME_URL}


# --- Records passed between members ----------------------------------------


def test_nested_record(edp, cap, self_contained_provider):
    edp_signed, edp_ids = edp_record(edp, self_contained_provider)
    cap_signed, cap_ids = cap_record(
        cap, self_contained_provider, edp_signed, edp_ids["transfer"]
    )
    encoded = cap_signed.encoded()

    # The EDP's signed list is included unchanged as the first element
    assert encoded["steps"][0] == edp_signed.encoded()["steps"]
    assert set(encoded["certificates"]) >= {str(edp.serial), str(cap.serial)}
    assert encoded["origins"] == [edp_ids["origin"]]

    steps = verify(encoded, self_contained_provider).decoded()
    by_type = {s["type"]: s for s in steps}
    cap_info = by_type["receipt"]["_signature"]["signed"]
    assert cap_info["member"] == cap.member
    assert by_type["transfer"]["_signature"]["signed"]["member"] == edp.member
    assert by_type["transfer"]["_signature"]["includedBy"] == [cap_info]
    assert by_type["receipt"]["_signature"]["includedBy"] == []
    assert by_type["receipt"]["transfer"] == edp_ids["transfer"]


def test_add_record_merges_origins_in_order(edp, cap, self_contained_provider):
    first, first_ids = edp_record(edp, self_contained_provider)
    second, second_ids = edp_record(edp, self_contained_provider)
    merged = Record(TRUST_FRAMEWORK_URL)
    merged.add_record(first)
    merged.add_record(second)
    merged.add_step(
        {"type": "process", "inputs": [first_ids["origin"], second_ids["origin"]]}
    )
    encoded = merged.sign(cap.signer(self_contained_provider)).encoded()
    assert encoded["origins"] == [first_ids["origin"], second_ids["origin"]]
    assert len(verify(encoded, self_contained_provider).decoded()) == 7


def test_sign_again_wraps_previous_list(edp, cap, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    again = Record(TRUST_FRAMEWORK_URL, signed.encoded()).sign(
        cap.signer(self_contained_provider)
    )
    steps = again.encoded()["steps"]
    assert len(steps) == 2 and steps[0] == signed.encoded()["steps"]
    verify(again.encoded(), self_contained_provider)


# --- Tampering and trust ---------------------------------------------------


@pytest.fixture
def signed_nested(edp, cap, self_contained_provider):
    edp_signed, edp_ids = edp_record(edp, self_contained_provider)
    cap_signed, _ = cap_record(
        cap, self_contained_provider, edp_signed, edp_ids["transfer"]
    )
    return cap_signed.encoded()


def test_untampered_nested_record_verifies(signed_nested, self_contained_provider):
    verify(signed_nested, self_contained_provider)


def test_changed_step_fails(signed_nested, self_contained_provider):
    tampered = copy.deepcopy(signed_nested)
    step = decode_step(tampered["steps"][1])
    step["scheme"] = "https://example.com/other-scheme"
    tampered["steps"][1] = encode_step(step)
    with pytest.raises(InvalidSignature):
        verify(tampered, self_contained_provider)


def test_changed_included_step_fails(signed_nested, self_contained_provider):
    tampered = copy.deepcopy(signed_nested)
    nested = tampered["steps"][0]
    step = decode_step(nested[0])
    step["account"] = "someone-else"
    nested[0] = encode_step(step)
    with pytest.raises(InvalidSignature):
        verify(tampered, self_contained_provider)


def test_removed_step_fails(signed_nested, self_contained_provider):
    tampered = copy.deepcopy(signed_nested)
    del tampered["steps"][2]  # process step
    with pytest.raises(InvalidSignature):
        verify(tampered, self_contained_provider)


def test_changed_signing_timestamp_fails(signed_nested, self_contained_provider):
    # One second earlier, still inside the certificate's validity, so only the
    # signature over the timestamp can detect it
    tampered = copy.deepcopy(signed_nested)
    signed_at = datetime.datetime.fromisoformat(tampered["steps"][-1][2])
    earlier = signed_at - datetime.timedelta(seconds=1)
    tampered["steps"][-1][2] = earlier.strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(InvalidSignature):
        verify(tampered, self_contained_provider)


def test_signing_time_outside_certificate_validity_fails(
    signed_nested, self_contained_provider
):
    tampered = copy.deepcopy(signed_nested)
    tampered["steps"][-1][2] = "2000-01-01T00:00:00Z"
    with pytest.raises(ChainError):
        verify(tampered, self_contained_provider)


def test_changed_included_signature_fails(signed_nested, self_contained_provider):
    tampered = copy.deepcopy(signed_nested)
    inner_signature = tampered["steps"][0][-1]
    inner_signature[3] = tampered["steps"][-1][3]  # signature from the outer list
    with pytest.raises(InvalidSignature):
        verify(tampered, self_contained_provider)


def test_changed_serial_fails(signed_nested, self_contained_provider):
    tampered = copy.deepcopy(signed_nested)
    tampered["steps"][-1][1] = "999"
    with pytest.raises(CertificateNotFoundError):
        verify(tampered, self_contained_provider)


def test_unknown_version_fails(signed_nested, self_contained_provider):
    tampered = copy.deepcopy(signed_nested)
    tampered["steps"][-1][0] = 1
    with pytest.raises(VerificationError, match="container format version"):
        verify(tampered, self_contained_provider)


def test_non_numeric_serial_fails(signed_nested, self_contained_provider):
    tampered = copy.deepcopy(signed_nested)
    tampered["steps"][-1][1] = "0123"
    with pytest.raises(VerificationError, match="serial"):
        verify(tampered, self_contained_provider)


def test_wrong_origins_fails(signed_nested, self_contained_provider):
    tampered = copy.deepcopy(signed_nested)
    tampered["origins"] = []
    with pytest.raises(VerificationError, match="origins"):
        verify(tampered, self_contained_provider)


def test_untrusted_root_fails(signed_nested):
    other_root = CertificatesProviderSelfContainedRecord(PKI().root_pem)
    with pytest.raises(ChainError):
        verify(signed_nested, other_root)


# --- Usage errors ----------------------------------------------------------


def test_add_step_rejects_id(edp):
    with pytest.raises(ValidationError, match="id"):
        Record(TRUST_FRAMEWORK_URL).add_step({"type": "origin", "id": "x"})


def test_add_step_rejects_underscore_keys():
    with pytest.raises(ValidationError, match="_signature"):
        Record(TRUST_FRAMEWORK_URL).add_step({"type": "origin", "_signature": {}})


def test_add_record_rejects_other_trust_framework(edp, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    other_framework = "https://example.com/other-framework"
    signed_other = Record(
        other_framework, {**signed.encoded(), "ib1:provenance": other_framework}
    )
    with pytest.raises(ValidationError):
        Record(TRUST_FRAMEWORK_URL).add_record(signed_other)


def test_add_record_rejects_non_record():
    with pytest.raises(TypeError):
        Record(TRUST_FRAMEWORK_URL).add_record({"steps": []})


def test_load_rejects_wrong_trust_framework(edp, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    with pytest.raises(ValidationError):
        Record("https://example.com/other-framework", signed.encoded())


def test_load_rejects_non_record():
    with pytest.raises(ValidationError):
        Record(TRUST_FRAMEWORK_URL, {"steps": "not a list"})


def test_unsigned_record_cannot_be_encoded():
    record = Record(TRUST_FRAMEWORK_URL)
    record.add_step({"type": "origin"})
    with pytest.raises(ProvenanceError, match="not signed"):
        record.encoded()


def test_unverified_record_cannot_be_decoded(edp, self_contained_provider):
    signed, _ = edp_record(edp, self_contained_provider)
    with pytest.raises(ProvenanceError, match="not verified"):
        signed.decoded()
    with pytest.raises(ProvenanceError, match="not verified"):
        signed.filter_steps({"type": "origin"})


# --- Finding steps ---------------------------------------------------------


@pytest.fixture
def verified_nested(signed_nested, self_contained_provider):
    return verify(signed_nested, self_contained_provider)


def test_find_step_by_type(verified_nested):
    assert verified_nested.find_step({"type": "origin"})["external"] is True


def test_find_step_by_nested_values(verified_nested, cap):
    step = verified_nested.find_step(
        {"type": "receipt", "_signature": {"signed": {"member": cap.member}}}
    )
    assert step["type"] == "receipt"
    assert (
        verified_nested.find_step(
            {"allows": {"licenses": [f"{SCHEME_URL}/license/1"]}}
        )["type"]
        == "permission"
    )


def test_find_step_with_missing_key_does_not_fail(verified_nested):
    # Not every step has "of", which raised KeyError in an earlier debug version
    assert (
        verified_nested.find_step(
            {"of": verified_nested.find_step({"type": "origin"})["id"]}
        )["type"]
        == "transfer"
    )


def test_find_step_no_match(verified_nested):
    with pytest.raises(ProvenanceError, match="No step matches"):
        verified_nested.find_step({"type": "nonexistent"})


def test_find_step_many_matches(verified_nested):
    with pytest.raises(ProvenanceError, match="More than one"):
        verified_nested.find_step({"scheme": SCHEME_URL})


def test_filter_steps(verified_nested):
    assert len(verified_nested.filter_steps({"scheme": SCHEME_URL})) == 5


def test_to_graphviz(verified_nested):
    dot = verified_nested.to_graphviz()
    assert dot.startswith("digraph ProvenanceRecord {")
    assert "[label=transfer]" in dot and "[label=inputs]" in dot
