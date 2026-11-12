# ib1-provenance

Python library to create, sign and verify records that follow the [IB1 Provenance Records 1.0 specification](https://specification.trust.ib1.org/provenance-records/1.0/).

Requires Python 3.11 or later. See [CHANGELOG.md](CHANGELOG.md) for changes between versions.

## Install

```
pip install ib1-provenance
```

To sign with a key held in AWS KMS, install the `kms` extra:

```
pip install "ib1-provenance[kms]"
```

## Use

A record is built from steps, then signed with a signing certificate issued by the Directory. A participant who receives a record verifies it, adds its own steps, and signs it again.

```python
from ib1.provenance import Record
from ib1.provenance.certificates import CertificatesProviderSelfContainedRecord
from ib1.provenance.signing import SignerFiles

TRUST_FRAMEWORK_URL = "https://registry.core.trust.ib1.org/trust-framework"

with open("signing-ca-root.pem", "rb") as f:
    provider = CertificatesProviderSelfContainedRecord(f.read())

# Create and sign a record
record = Record(TRUST_FRAMEWORK_URL)
origin_id = record.add_step({"type": "origin", "scheme": "...", ...})
record.add_step({"type": "transfer", "of": origin_id, "scheme": "...", ...})
signer = SignerFiles(provider, "signing-bundle.pem", "signing-key.pem")
signed = record.sign(signer)
attachment = signed.encoded()  # JSON-serialisable dict to send with the data

# Receive and verify a record
received = Record(TRUST_FRAMEWORK_URL, attachment)
received.verify(provider)
transfer = received.find_step({"type": "transfer", "to": "https://directory.core.trust.ib1.org/member/81524"})
received.require_signer(transfer["id"], role="https://registry.core.trust.ib1.org/scheme/perseus/role/energy-data-provider")
```

`main.py` has a full example of a record passed between three members.

### Certificate providers

- `CertificatesProviderSelfContainedRecord` includes the signing certificate and its issuer chain in the record, and uses them to verify. Use this one unless you have a reason not to.
- `CertificatesProviderLocal` reads certificates from a local directory and leaves them out of the record, which makes it smaller.

Both take the signing root CA certificate from the Directory. A root CA certificate included in a record is never trusted.

### Signers

- `SignerFiles` reads the certificate bundle and private key from PEM files.
- `SignerInMemory` takes `cryptography` certificate and key objects.
- `SignerKMS` signs with a key in AWS KMS. It needs the `kms` extra.

### Checks

`add_step()` and `sign()` check that new steps follow the specification: step types, timestamps, references between steps, and at least one origin step. They raise `ValidationError`, and `sign()` raises before the signer is called.

`verify()` checks signatures, certificates and the structure of the signed record. It does not repeat the step checks, so records signed by older versions still verify. To check the steps of a received record, call `validate()` after `verify()`. It returns a list of problems and does not raise.

Revocation is not checked yet, see [directory#272](https://github.com/icebreakerone/directory/issues/272).

### Exceptions

All exceptions raised by the library subclass `ProvenanceError`, which can be imported from `ib1.provenance`:

- `ValidationError`, a record or step does not follow the specification
- `VerificationError`, a signed record could not be verified
- `CertificateError`, a certificate is missing or does not have the expected contents
- `CertificateNotFoundError`, a certificate serial number is not available. It is also a `KeyError`.

A bad signature raises `cryptography.exceptions.InvalidSignature`. A certificate chain which is not valid at the signing time raises `cryptography.x509.verification.VerificationError`.

## Develop

```
pipx install poetry
poetry install
poetry run pytest
poetry run ruff check .
```

`tests/vectors/` holds a signed record and the exact data that was signed, for checking other implementations against this one. `tests/vectors/generate.py` regenerates them.

### Run the example

`main.py` needs a set of test certificates, which `scripts/certmaker.sh` creates. The certificates expire, so run it again if the example fails with "cert is not valid at validation time".

```
mkdir certs
cd certs
sh ../scripts/certmaker.sh
cd ..
poetry run python main.py
```

### Decode a record

```
poetry run python decode-self-contained-provenance.py path/to/signing-CA-root.pem < record.json
```

## Publish the library

1. Add the release notes to `CHANGELOG.md`.
2. Change `version` in `pyproject.toml`.
3. Merge to `main`, then tag the merge commit, for example `git tag v0.6.0 && git push origin v0.6.0`.
4. Build and publish:

```
poetry build
poetry publish
```
