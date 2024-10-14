import base64
import json
import copy


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
        self._verified = False

    def verify(self, certificates):
        self._require_signed()
        self._verify(self._record, certificates)

    def _verify(self, level, certificates):
        serial, *data, signature = level
        # Serial number must only be a number
        if str(int(serial)) != serial:
            raise Exception("Bad certificate serial number in record: "+serial)
        # Check signatures at this level
        certificates._verify(serial, self._data_for_signing(data).encode("utf-8"), base64.urlsafe_b64decode(signature))
        # Recurse into signed data
        for e in data:
            if not isinstance(e, str):
                self._verify(e, certificates)
        self._verified = True

    def add_record(self, record):
        self._signed = False
        self._verified = False
        self._additional_records.append(record)

    def add_step(self, step):
        self._signed = False
        self._verified = False
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
        output.insert(0, serial)
        output.append(base64.urlsafe_b64encode(signature).decode('utf-8'))
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

    def _require_signed(self):
        if not self._signed:
            raise Exception("Record is not signed, call sign() and use returned object")
