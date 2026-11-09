"""Regenerate the test vectors in this directory.

    uv run python tests/vectors/generate.py

Each run creates new keys, so record.json and root-ca.pem change. The signature
data strings and decoded steps stay the same. Private keys are not saved.
"""

import datetime
import itertools
import json
import pathlib
import sys
from unittest.mock import patch

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))

from pki import PKI, SCHEME_URL, TRUST_FRAMEWORK_URL  # noqa: E402

from ib1.provenance import Record  # noqa: E402
from ib1.provenance.certificates import (  # noqa: E402
    CertificatesProviderSelfContainedRecord,
)

# Certificates are valid long enough that the vectors don't expire
NOT_BEFORE = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2124, 1, 1, tzinfo=datetime.timezone.utc)

EDP_SIGNED_AT = "2024-09-16T15:40:00Z"
CAP_SIGNED_AT = "2024-09-16T16:05:12Z"
IDS = {
    "permission": "V1VFKWxXsXUtiaFEInSF",
    "origin": "4cN6b85eT7F5MCTTxhiI",
    "transfer": "51H_KU9Yw4VDxLnaIx-O",
    "receipt": "lQo4LTEXAG7SMPlZ6t7a",
    "process": "Pq7Xk2LmN9vR4tYw1ZsB",
}

# The worked example in the Provenance Records specification, "Signature data"
SPEC_EXAMPLE = {
    "steps": [
        ["STEP_A", [0, "1001", "2024-09-16T15:32:56Z", "SIGNATURE_1"]],
        "STEP_B",
        [0, "2002", "2024-09-16T16:05:12Z", "SIGNATURE_2"],
    ],
    "signature_data": (
        "https://registry.core.trust.ib1.org/trust-framework"
        ".%.STEP_A.%.0.1001.2024-09-16T15:32:56Z.SIGNATURE_1.&.&.STEP_B"
        ".0.2002.2024-09-16T16:05:12Z"
    ),
}


def sign_at(record, signer, timestamp):
    with patch.object(Record, "_timestamp_now_iso8601", return_value=timestamp):
        return record.sign(signer)


def build():
    pki = PKI(not_before=NOT_BEFORE, not_after=NOT_AFTER)
    edp = pki.member(
        "Smart Meter Reading Co",
        2876152,
        38936455,
        [f"{SCHEME_URL}/role/energy-data-provider"],
        123456,
    )
    cap = pki.member(
        "Carbon Accounting Provider",
        81524,
        26241,
        [f"{SCHEME_URL}/role/carbon-accounting-provider"],
        98765,
    )
    provider = CertificatesProviderSelfContainedRecord(pki.root_pem)
    ids = iter(IDS.values())

    with patch(
        "ib1.provenance.record.globally_unique_step_identifier", lambda: next(ids)
    ):
        record = Record(TRUST_FRAMEWORK_URL)
        record.add_step(
            {
                "type": "permission",
                "timestamp": "2024-09-16T15:32:56Z",
                "scheme": SCHEME_URL,
                "account": "iuPgAg4c8x4diYfdl6ADN4ULy3ir_B88",
                "allows": {
                    "licenses": [
                        f"{SCHEME_URL}/license/energy-consumption-data/2024-12-05"
                    ],
                    "processes": [
                        f"{SCHEME_URL}/process/emissions-calculation/2024-12-05"
                    ],
                },
                "expires": "2025-09-16T15:32:56Z",
            }
        )
        record.add_step(
            {
                "type": "origin",
                "timestamp": "2024-09-16T15:32:56Z",
                "scheme": SCHEME_URL,
                "sourceType": f"{SCHEME_URL}/source-type/Meter",
                "origin": "https://www.smartdcc.co.uk/",
                "originLicense": "https://smartenergycodecompany.co.uk/documents/sec/consolidated-sec/",
                "external": True,
                "permissions": [IDS["permission"]],
                # Non-ASCII text checks the JSON encoding (escaped as é)
                "perseus:scheme": {"note": "café"},
            }
        )
        record.add_step(
            {
                "type": "transfer",
                "timestamp": "2024-09-16T15:32:56Z",
                "scheme": SCHEME_URL,
                "of": IDS["origin"],
                "to": cap.member,
                "standard": f"{SCHEME_URL}/standard/energy-consumption-data/2024-12-05",
                "license": f"{SCHEME_URL}/license/energy-consumption-data/2024-12-05",
                "service": "https://api.example.com/v1/consumption",
                "path": "/readings",
                "parameters": {
                    "measure": "import",
                    "from": "2023-10-18",
                    "to": "2023-10-19",
                },
                "permissions": [IDS["permission"]],
            }
        )
        edp_signed = sign_at(record, edp.signer(provider), EDP_SIGNED_AT)

        record = Record(TRUST_FRAMEWORK_URL, edp_signed.encoded())
        record.add_step(
            {
                "type": "receipt",
                "timestamp": "2024-09-16T16:00:00Z",
                "scheme": SCHEME_URL,
                "transfer": IDS["transfer"],
            }
        )
        record.add_step(
            {
                "type": "process",
                "timestamp": "2024-09-16T16:05:00Z",
                "scheme": SCHEME_URL,
                "inputs": [IDS["receipt"]],
                "process": f"{SCHEME_URL}/process/emissions-calculation/2024-12-05",
            }
        )
        cap_signed = sign_at(record, cap.signer(provider), CAP_SIGNED_AT)

    encoded = cap_signed.encoded()
    verified = Record(TRUST_FRAMEWORK_URL, encoded)
    verified.verify(provider)

    outer = encoded["steps"]
    inner = outer[0]
    expected = {
        "description": "Expected values for record.json, verified with root-ca.pem",
        "trust_framework": TRUST_FRAMEWORK_URL,
        "signature_data": {
            # Signature data for each Signed Step List, outermost first
            "steps": verified._data_for_signing(
                outer[:-1], [str(v) for v in outer[-1][:3]]
            ),
            "steps[0]": verified._data_for_signing(
                inner[:-1], [str(v) for v in inner[-1][:3]]
            ),
        },
        "decoded_steps": verified.decoded(),
    }

    (HERE / "root-ca.pem").write_bytes(pki.root_pem)
    (HERE / "record.json").write_text(json.dumps(encoded, indent=2) + "\n")
    (HERE / "expected.json").write_text(
        json.dumps(expected, indent=2, ensure_ascii=False) + "\n"
    )
    (HERE / "spec-example.json").write_text(json.dumps(SPEC_EXAMPLE, indent=2) + "\n")


if __name__ == "__main__":
    build()
    print(
        "Wrote",
        ", ".join(
            p.name for p in itertools.chain(HERE.glob("*.json"), HERE.glob("*.pem"))
        ),
    )
