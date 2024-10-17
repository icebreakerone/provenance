import base64
import json
import copy
import datetime


class Record:

    # data attributes:
    #   _record -- signed record as output from JSON decoding
    #   _additional_records -- array of signed records to add to the record
    #   _additional_steps -- array of steps to add to the record
    #   _signed -- whether the record is completely signed
    #   _verified -- whether the record has had signatures verified

    def __init__(self, record=None):
        self._record = record
        self._additional_records = []
        self._additional_steps = []
        self._signed = True
        self._verified = None

    def verify(self, certificates):
        self._require_signed()
        # Recursively verify record
        steps = []
        signer_stack = []
        self._verify_record_container(self._record, certificates, steps, signer_stack)
        self._verified = steps

    def _verify_record_container(self, container, certificates, steps, signer_stack):
        *data, sig_block = container
        serial, sign_timestamp, signature = sig_block
        # Serial number must only be a number
        if str(int(serial)) != serial:
            raise Exception("Bad certificate serial number in record: "+serial)
        # Check signatures at this level and get signer information
        signer_info = certificates._verify(serial, sign_timestamp, self._data_for_signing(data).encode("utf-8"), base64.urlsafe_b64decode(signature))
        # Recurse into signed data, collecting decoded steps and adding signer info
        for e in data:
            if not isinstance(e, str):
                signer_stack.append(signer_info)
                self._verify_record_container(e, certificates, steps, signer_stack)
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
        self._additional_records.append(record)

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
        if self._record is not None:
            output.append(self._record) # signed and encoded
        for r in self._additional_records:
            if isinstance(r, Record):
                r = r.encoded()
            output.append(r) # signed and encoded
        for s in self._additional_steps:
            output.append(self._encode_step(s)) # unencoded, not signed
        serial, signature = signer._sign(self._data_for_signing(output).encode("utf-8"))
        output.append([
            serial,
            self._timestamp_now_iso8601(),
            base64.urlsafe_b64encode(signature).decode('utf-8')
        ])
        return Record(copy.deepcopy(output))

    def _encode_step(self, step):
        return base64.urlsafe_b64encode(json.dumps(step, separators=(",", ":")).encode("utf-8")).decode('utf-8')

    def _data_for_signing(self, data):
        gather = []
        for e in data:
            if isinstance(e, str):
                gather.append(e)
            else:
                gather.append("%")
                gather.append(self._data_for_signing(e))
                gather.append("&")
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
