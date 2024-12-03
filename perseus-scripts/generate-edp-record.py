import json

from ib1.provenance import Record
from ib1.provenance.signing import SignerFiles
from ib1.provenance.certificates import CertificatesProviderSelfContainedRecord

TRUST_FRAMEWORK_URL = "https://registry.core.pilot.trust.ib1.org/trust-framework"

if __name__ == "__main__":
    certificate_provider = CertificatesProviderSelfContainedRecord(
        "perseus-scripts/in-edp/signing-ca-root.pem"
    )

    signer_edp = SignerFiles(
        certificate_provider,
        "perseus-scripts/in-edp/signer-cert-bundle.pem",
        "perseus-scripts/in-edp/signer.key"
    )

    with open("perseus-scripts/in-edp/details.json") as f:
        details = json.loads(f.read())

    edp_record = Record(TRUST_FRAMEWORK_URL)

    # - Permission step to record consent by end user
    edp_permission_id = edp_record.add_step(
        {
            "type": "permission",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "timestamp": details["permissionGranted"],
            "account": details["userAccountIdentifier"],
            "allows": {
                "licences": [
                    "https://smartenergycodecompany.co.uk/documents/sec/consolidated-sec/",
                    "https://registry.core.pilot.trust.ib1.org/scheme/perseus/licence/energy-consumption-data/2024-12-05"
                ]
            },
            "expires": details["permissionExpires"]
        }
    )
    # - Origin step for the smart meter data
    origin_id = edp_record.add_step(
        {
            "type": "origin",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "sourceType": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/source-type/Meter",
            "origin": "https://www.smartdcc.co.uk/",
            "originLicence": "https://smartenergycodecompany.co.uk/documents/sec/consolidated-sec/",
            "external": True,
            "permissions": [edp_permission_id],
            "perseus:scheme": {
                "meteringPeriod": {
                    "from": details["periodFrom"],
                    "to": details["periodTo"]
                }
            },
            "perseus:assurance": details["assurance"]
        }
    )
    # - Transfer step to send it to the CAP
    edp_record.add_step(
        {
            "type": "transfer",
            "scheme": "https://registry.core.pilot.trust.ib1.org/scheme/perseus",
            "of": origin_id,
            "to": details["capURL"],
            "standard": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/standard/energy-consumption-data/2024-12-05",
            "licence": "https://registry.core.pilot.trust.ib1.org/scheme/perseus/licence/energy-consumption-data/2024-12-05",
            "service": details["service"],
            "path": "/readings",
            "parameters": {
                "measure": "import",
                "from": details["periodFrom"],
                "to": details["periodTo"]
            },
            "permissions": [edp_permission_id],
            "transaction": details["transaction"]
        }
    )
    # EDP signs the steps
    edp_record_signed = edp_record.sign(signer_edp)
    # Get encoded data for inclusion in data response
    edp_data_attachment = edp_record_signed.encoded()

    with open("perseus-scripts/out/edp-record.json", "w") as f:
        f.write(json.dumps(edp_data_attachment, indent=2))
    with open("perseus-scripts/out/edp-record-decoded.json", "w") as f:
        edp_record_signed.verify(certificate_provider)
        f.write(json.dumps(edp_record_signed.decoded(), indent=2))
    with open("perseus-scripts/out/edp-record.dot", "w") as f:
        f.write(edp_record_signed.to_graphviz())
