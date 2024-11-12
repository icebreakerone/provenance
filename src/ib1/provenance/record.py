import base64
import json
import copy
import datetime

from cryptography.hazmat.primitives import serialization


class Record:

    # data attributes:
    #   _record -- signed record as output from JSON decoding
    #   _additional_records -- array of signed records to add to the record
    #   _additional_steps -- array of steps to add to the record
    #   _signed -- whether the record is completely signed
    #   _verified -- whether the record has had signatures verified

    def __init__(self, record=None):
        if record is not None:
            if not isinstance(record.get("steps"), list):
                raise Exception("Not an encoded Provenance record")
        self._record = record
        self._additional_records = []
        self._additional_steps = []
        self._signed = True
        self._verified = None

    def verify(self, certificate_provider):
        self._require_signed()
        # Recursively verify record
        steps = []
        signer_stack = []
        certificates_from_record = self._record.get("certificates")
        if certificates_from_record is None:
            certificates_from_record = {}
        self._verify_record_container(self._record["steps"], certificates_from_record, certificate_provider, steps, signer_stack)
        self._verified = steps

    def _verify_record_container(self, container, certificates_from_record, certificate_provider, steps, signer_stack):
        *data, sig_block = container
        serial, sign_timestamp, signature = sig_block
        # Serial number must only be a number
        if str(int(serial)) != serial:
            raise Exception("Bad certificate serial number in record: "+serial)
        # Check signatures at this level and get signer information
        data_for_signing = self._data_for_signing(data, [serial, sign_timestamp])
        signer_info = certificate_provider._verify(certificates_from_record, serial, sign_timestamp, data_for_signing.encode("utf-8"), base64.urlsafe_b64decode(signature))
        # Recurse into signed data, collecting decoded steps and adding signer info
        for e in data:
            if not isinstance(e, str):
                signer_stack.append(signer_info)
                self._verify_record_container(e, certificates_from_record, certificate_provider, steps, signer_stack)
                del signer_stack[-1]
            else:
                decoded_step = json.loads(base64.urlsafe_b64decode(e))
                decoded_step[".signature"] = {
                    "signed": signer_info,
                    "includedBy": copy.copy(signer_stack)
                }
                steps.append(decoded_step)

    def add_record(self, record):
        self._signed = False
        self._verified = None
        if not isinstance(record, Record):
            raise Exception("Not a Record object")
        self._additional_records.append(record.encoded())

    def add_step(self, step_in):
        self._signed = False
        self._verified = None
        step = copy.deepcopy(step_in)
        if not "timestamp" in step:
            step["timestamp"] = self._timestamp_now_iso8601()
            # TODO: Verify timestamp is in the right format (and maybe signing cert is valid at that time?)
        if ".signature" in step:
            raise Exception("Step may not contain .signature key")
        self._additional_steps.append(step)

    def sign(self, signer):
        output = []
        certificates = {}
        if self._record is not None:
            if "certificates" in self._record:
                certificates.update(self._record["certificates"])
            output.append(self._record["steps"]) # signed and encoded
        for r in self._additional_records:
            if "certificates" in r:
                certificates.update(r["certificates"])
            output.append(r["steps"]) # signed and encoded
        for s in self._additional_steps:
            output.append(self._encode_step(s)) # unencoded, not signed
        serial = signer._serial()
        sign_timestamp = self._timestamp_now_iso8601()
        data_for_signing = self._data_for_signing(output, [serial, sign_timestamp])
        signature = signer._sign(data_for_signing.encode("utf-8"))
        output.append([
            serial,
            sign_timestamp,
            base64.urlsafe_b64encode(signature).decode('utf-8')
        ])
        if not serial in certificates:
            certs_for_record = signer._certificates_for_record()
            if certs_for_record is not None:
                # Represent path as [pem encoded cert, serials of issuer chain ...]
                first_cert, *other_certs = certs_for_record
                cert_path = [first_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")]
                cert_path.append(*list(map(
                    lambda c: str(c.serial_number), other_certs
                )))
                certificates[serial] = cert_path
                for c in other_certs:
                    certificates[str(c.serial_number)] = [c.public_bytes(serialization.Encoding.PEM).decode("utf-8")]
        encoded = {"steps": copy.deepcopy(output)}
        if certificates:
            encoded["certificates"] = certificates
        return Record(encoded)

    def _encode_step(self, step):
        return base64.urlsafe_b64encode(json.dumps(step, separators=(",", ":")).encode("utf-8")).decode('utf-8')

    def _data_for_signing(self, data, additional=None):
        gather = []
        for e in data:
            if isinstance(e, str):
                gather.append(e)
            else:
                gather.append("%")
                gather.append(self._data_for_signing(e))
                gather.append("&")
        if additional is not None:
            gather.extend(additional)
        return ".".join(gather)

    def encoded(self): # TODO name
        self._require_signed()
        return self._record

    def decoded(self): # TODO name
        self._require_verified()
        return copy.deepcopy(self._verified)

    def _require_signed(self):
        if not self._signed:
            raise Exception("Record is not signed, call sign() and use returned object")

    def _require_verified(self):
        if not (self._signed and (self._verified != None)):
            raise Exception("Record is not verified, call verify() first")

    def _timestamp_now_iso8601(self):
        return (datetime.datetime.now(datetime.UTC).
            replace(microsecond=0).
            isoformat().
            replace("+00:00", "Z")
        )