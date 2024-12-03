import json

from ib1.provenance import Record
from ib1.provenance.signing import SignerFiles
from ib1.provenance.certificates import CertificatesProviderSelfContainedRecord

TRUST_FRAMEWORK_URL = "https://registry.core.pilot.trust.ib1.org/trust-framework"

if __name__ == "__main__":
    certificate_provider = CertificatesProviderSelfContainedRecord(
        "perseus-scripts/in-cap/signing-ca-root.pem"
    )

    signer_cap = SignerFiles(
        certificate_provider,
        "perseus-scripts/in-cap/signer-cert-bundle.pem",
        "perseus-scripts/in-cap/signer.key"
    )

    with open("perseus-scripts/in-cap/details.json") as f:
        details = json.loads(f.read())

    with open("perseus-scripts/in-cap/edp-record.json") as f:
        edp_data_attachment = json.loads(f.read())

    cap_record = Record(TRUST_FRAMEWORK_URL, edp_data_attachment)

    # - Verify the signatures on the record
    cap_record.verify(certificate_provider)

    # - Find the transfer step, passing in the expected values for the transfer step (exceptions if not found)
    transfer_from_edp_step = cap_record.find_step(
        {
            # Same values as the transfer step added by the EDP
            # NOTE: In a real application the find parameters would be much more specific.
            "type": "transfer",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "standard": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/standard/energy-consumption-data/2024-12-05",
            "licence": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/licence/energy-consumption-data/2024-12-05"
        }
    )
    # - Add a receipt step
    cap_receipt_id = cap_record.add_step(
        {
            "type": "receipt",
            "transfer": transfer_from_edp_step["id"]
        }
    )
    # - Permission step to record consent to processing and future transfer
    cap_permission_id = cap_record.add_step(
        {
            "type": "permission",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "timestamp": details["permissionGranted"],
            "account": details["userAccountIdentifier"],
            "allows": {
                "licences": [
                    "https://registry.core.pilot.trust.ib1.org/scheme/perseus/licence/emissions-report/2024-12-05"
                ],
                "processes": [
                    "https://registry.core.pilot.trust.ib1.org/scheme/perseus/process/emissions-calculations/2024-12-05"
                ]
            },
            "expires": details["permissionExpires"]
        }
    )
    # - Add an origin step for grid intensity data
    cap_intensity_origin_id = cap_record.add_step(
        {
            "type": "origin",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "sourceType": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/source-type/GridCarbonIntensity",
            "origin": "https://api.carbonintensity.org.uk/",
            "originLicence": "https://creativecommons.org/licenses/by/4.0/",
            "external": True,
            "perseus:scheme": {
                "meteringPeriod": {
                    "from": details["periodFrom"],
                    "to": details["periodTo"]
                },
                "postcode": details["postcode"]
            },
            "perseus:assurance": {
                "missingData": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/assurance/missing-data/Complete"
            }
        }
    )
    # - Add a process step to combine the data from the EDP and the grid intensity API into the report
    cap_processing_id = cap_record.add_step(
        {
            "type": "process",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "inputs": [
                cap_receipt_id,
                cap_intensity_origin_id
            ],
            "process": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/process/emissions-calculations/2024-12-05",
            "permissions": [cap_permission_id],
            "perseus:assurance": details["assurance"]
        }
    )
    # - Add a transfer step to send it to the bank
    cap_record.add_step(
        {
            "type": "transfer",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "of": cap_processing_id,
            "to": "https://directory.core.pilot.trust.ib1.org/member/71212388", # Bank
            "standard": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/standard/emissions-report/2024-12-05",
            "licence": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/licence/emissions-report/2024-12-05",
            "service": details["service"],
            "path": "/emissions",
            "parameters": {
                "from": "2023-09Z",
                "to": "2024-09Z"
            },
            "permissions": [cap_permission_id],
            "transaction": details["transaction"]
        }
    )

    # CAP signs the steps
    cap_record_signed = cap_record.sign(signer_cap)
    # Get encoded data for inclusion in data response
    cap_data_attachment = cap_record_signed.encoded()

    with open("perseus-scripts/out/cap-record.json", "w") as f:
        f.write(json.dumps(cap_data_attachment, indent=2))
    with open("perseus-scripts/out/cap-record-decoded.json", "w") as f:
        cap_record_signed.verify(certificate_provider)
        f.write(json.dumps(cap_record_signed.decoded(), indent=2))
    with open("perseus-scripts/out/cap-record.dot", "w") as f:
        f.write(cap_record_signed.to_graphviz())
