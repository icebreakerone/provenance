# Changelog

## 0.6.0

This release aligns the library with the [Provenance Records 1.0 specification](https://specification.trust.ib1.org/provenance-records/1.0/). The specification was updated to describe the library's signing and encoding format ([ib1-technical-specifications#15](https://github.com/icebreakerone/ib1-technical-specifications/pull/15)), so that format does not change. Records signed by 0.5.3 are signed the same way and still verify, unless they are malformed in one of the ways listed under "Breaking changes".

### Breaking changes

- Python 3.11 or later is required. 0.5.3 declared support for 3.10 but did not work on it.
- `Record.verify()` rejects malformed records that 0.5.3 accepted:
  - the signing certificate's serial number must match the serial number in the signature
  - the signature element must have 4 items: an integer version, a serial number matching `^(0|[1-9][0-9]*)$`, a timestamp in `YYYY-MM-DDTHH:MM:SSZ` form and a string signature
  - step IDs must be unique within the record
  - every issuer certificate listed for a signing certificate must be present in the record
- Loading a record with `Record(trust_framework, record)` checks that `origins` is a list and `certificates` is a map.
- `Record.add_step()` checks each new step, see "Step checks" below.
- `Record.sign()` checks the record before calling the signer, see "Step checks" below.
- Errors are raised as the library's own exception classes instead of `Exception`. They all subclass `Exception`, so `except Exception` still catches them. `add_record()` with something other than a `Record` raises `TypeError`.

### Step checks

These checks apply to new steps only. `verify()` does not apply them, so records signed before 0.6.0 still verify.

- `add_step()` raises `ValidationError` when:
  - `type` is missing or is not one of `permission`, `origin`, `transfer`, `receipt` or `process`
  - `timestamp`, or `expires` on a permission step, is not an ISO 8601 time in UTC ending in `Z`, such as `2024-09-16T15:32:56Z`
  - `of` or `transfer` is not a step ID, or `inputs` or `permissions` is not a list of step IDs
- `sign()` raises `ValidationError`, before the signer is called, when:
  - the record has no origin step
  - step IDs are used more than once
  - a new step refers to a step that is not in the record, or to the wrong type of step. `of` must refer to an origin, process or receipt step, `transfer` to a transfer step, `inputs` to origin, receipt or process steps, and `permissions` to permission steps.
- Steps in included records are not checked when signing, because other participants signed them.
- `Record.validate()` returns a list of these problems for a verified record, without raising. An empty list means none were found. It also reports top-level properties other than `ib1:provenance`, `origins`, `steps` and `certificates`, which the specification does not allow. These are not rejected when loading, because they are not signed: anyone could add one in transit, and rejecting the record would stop a correctly signed record being used. `sign()` leaves them out of the new record.

Callers which build timestamps with `isoformat()[0:-7] + "Z"` produce invalid values for times with a time zone or without microseconds, and will need fixing before upgrading. See [provenance-service#2](https://github.com/icebreakerone/provenance-service/issues/2) and [perseus-demo-energy#150](https://github.com/icebreakerone/perseus-demo-energy/issues/150).

### Added

- Exceptions, importable from `ib1.provenance`:
  - `ProvenanceError`, the base class
  - `ValidationError`, a record or step does not follow the specification
  - `VerificationError`, a signed record could not be verified
  - `CertificateError`, a certificate is missing or does not have the expected contents
  - `CertificateNotFoundError`, a certificate serial number is not available. Also a `KeyError`, which 0.5.3 raised in this case.
- `Record.require_signer(step_id, *, member=None, application=None, role=None)` checks who signed a step and returns it.
- `Record.validate()`, described above.
- Tests for signing, verification, nesting and tampering, and test vectors in `tests/vectors/` which include the worked example from the specification.

### Not changed

- Revocation is not checked. The Directory does not publish certificate revocation lists yet, see [directory#272](https://github.com/icebreakerone/directory/issues/272).
- A bad signature still raises `cryptography.exceptions.InvalidSignature`, and a certificate chain which is not valid at the signing time still raises `cryptography.x509.verification.VerificationError`. They are not wrapped in the library's exceptions.

## 0.5.3 and earlier

Not recorded in this file. See the git history.
