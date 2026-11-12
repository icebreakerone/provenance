import base64
import binascii
import copy
import datetime
import json

from cryptography.hazmat.primitives import serialization

from .certificates import SERIAL_PATTERN
from .exceptions import ProvenanceError, ValidationError, VerificationError
from .identifier import globally_unique_step_identifier
from . import validation


CURRENT_CONTAINER_FORMAT_VERSION = 0

# The specification does not allow any other top level properties. They are
# not signed and are dropped when the record is signed again, so validate()
# reports them instead of rejecting the record.
TOP_LEVEL_KEYS = {"ib1:provenance", "origins", "steps", "certificates"}

TIMESTAMP_PATTERN = validation.TIMESTAMP_PATTERN


class Record:
    # data attributes:
    #   _record -- signed record as output from JSON decoding
    #   _additional_records -- array of signed records to add to the record
    #   _additional_steps -- array of steps to add to the record
    #   _signed -- whether the record is completely signed
    #   _verified -- whether the record has had signatures verified

    def __init__(self, trust_framework, record=None):
        if record is not None:
            if not isinstance(record, dict) or not isinstance(
                record.get("steps"), list
            ):
                raise ValidationError("Not an encoded Provenance record")
            if trust_framework != record.get("ib1:provenance"):
                raise ValidationError(
                    "Unexpected trust framework when creating Record from encoded form"
                )
            if not isinstance(record.get("origins"), list):
                raise ValidationError("Provenance record origins must be a list")
            if not isinstance(record.get("certificates", {}), dict):
                raise ValidationError("Provenance record certificates must be a map")
        self.trust_framework = trust_framework
        self._record = record
        self._additional_records = []
        self._additional_steps = []
        self._signed = True
        self._verified = None

    def verify(self, certificate_provider):
        self._require_signed()
        # Recursively verify record
        steps = []
        origins = []
        signer_stack = []
        certificates_from_record = self._record.get("certificates")
        if certificates_from_record is None:
            certificates_from_record = {}
        self._verify_record_container(
            self._record["steps"],
            certificates_from_record,
            certificate_provider,
            steps,
            origins,
            signer_stack,
        )
        if self._record["origins"] != origins:
            raise VerificationError(
                "origins property does not match origin steps in record"
            )
        duplicates = self._duplicate_ids(steps)
        if duplicates:
            raise VerificationError(
                "Step ids are used more than once: " + ", ".join(duplicates)
            )
        self._verified = steps

    def _verify_record_container(
        self,
        container,
        certificates_from_record,
        certificate_provider,
        steps,
        origins,
        signer_stack,
    ):
        self._check_container_shape(container)
        *data, sig_block = container
        container_format_version, serial, sign_timestamp, signature = sig_block
        # Check it's an understood format (multiple versions of formats may be included in a single record)
        if container_format_version != CURRENT_CONTAINER_FORMAT_VERSION:
            raise VerificationError(
                "Cannot decode container format version: "
                + str(container_format_version)
            )
        # Check signatures at this level and get signer information
        data_for_signing = self._data_for_signing(
            data, [str(container_format_version), serial, sign_timestamp]
        )
        signer_info = certificate_provider.verify(
            certificates_from_record,
            serial,
            sign_timestamp,
            data_for_signing.encode("utf-8"),
            self._b64decode(signature, "Signature"),
        )
        # Recurse into signed data, collecting decoded steps and adding signer info
        for e in data:
            if not isinstance(e, str):
                signer_stack.append(signer_info)
                self._verify_record_container(
                    e,
                    certificates_from_record,
                    certificate_provider,
                    steps,
                    origins,
                    signer_stack,
                )
                del signer_stack[-1]
            else:
                decoded_step = self._decode_step(e)
                if decoded_step.get("type") == "origin":
                    origins.append(decoded_step.get("id"))
                decoded_step["_signature"] = {
                    "signed": signer_info,
                    "includedBy": copy.copy(signer_stack),
                }
                steps.append(decoded_step)

    @staticmethod
    def _check_container_shape(container):
        """Check a Signed Step List has the structure the specification requires."""
        if not isinstance(container, list) or len(container) < 2:
            raise VerificationError(
                "A Signed Step List must contain at least one element and a signature"
            )
        *data, sig_block = container
        for e in data:
            if not isinstance(e, (str, list)):
                raise VerificationError(
                    "A Signed Step List may only contain steps and other Signed Step Lists"
                )
        if not isinstance(sig_block, list) or len(sig_block) != 4:
            raise VerificationError("A signature element must be an array of 4 items")
        version, serial, sign_timestamp, signature = sig_block
        if not isinstance(version, int) or isinstance(version, bool):
            raise VerificationError("Container format version must be a number")
        if not isinstance(serial, str) or not SERIAL_PATTERN.match(serial):
            raise VerificationError(
                f"Bad certificate serial number in record: {serial!r}"
            )
        if not isinstance(sign_timestamp, str) or not TIMESTAMP_PATTERN.match(
            sign_timestamp
        ):
            raise VerificationError(
                f"Bad signing timestamp in record: {sign_timestamp!r}"
            )
        if not isinstance(signature, str):
            raise VerificationError("Signature must be a string")

    @staticmethod
    def _b64decode(value, what):
        try:
            # Accept values with or without padding
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (binascii.Error, ValueError):
            raise VerificationError(f"{what} is not base64url encoded") from None

    def _decode_step(self, encoded):
        try:
            step = json.loads(self._b64decode(encoded, "Step"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise VerificationError("Step is not encoded JSON") from None
        if not isinstance(step, dict):
            raise VerificationError("Step is not a JSON object")
        return step

    @staticmethod
    def _duplicate_ids(steps):
        return validation.duplicate_ids(steps)

    def add_record(self, record):
        self._signed = False
        self._verified = None
        if not isinstance(record, Record):
            raise TypeError("Not a Record object")
        if self.trust_framework != record.trust_framework:
            raise ValidationError("Incompatible trust frameworks in added Record")
        self._additional_records.append(record.encoded())

    def add_step(self, step_in):
        self._signed = False
        self._verified = None
        step = copy.deepcopy(step_in)
        # Step identifier
        if "id" in step:
            raise ValidationError(
                "Step may not contain an id key. Identifiers are allocated automatically and returned by this function."
            )
        id = globally_unique_step_identifier()
        # Step timestamp
        timestamp = step.pop("timestamp", None)
        if not timestamp:
            timestamp = self._timestamp_now_iso8601()
        # Step type
        step_type = step.pop("type", None)
        # No keys with _ prefix allowed
        prohibited_keys_present = list(filter(lambda k: k.startswith("_"), step.keys()))
        if prohibited_keys_present:
            raise ValidationError(
                "Step may not contain keys beginning with an underscore. Prohibited keys present: "
                + (", ".join(prohibited_keys_present))
            )
        new_step = {"id": id, "timestamp": timestamp, "type": step_type, **step}
        problems = validation.step_problems(new_step, label="New step")
        if problems:
            raise ValidationError("; ".join(problems))
        # Add to list of steps pending addition
        self._additional_steps.append(new_step)
        return id

    def validate(self):
        """Return a list of structural problems in a verified record.

        An empty list means no problems were found. This does not raise, so a
        record signed by another participant can be checked and the problems
        reported, without stopping it being used.
        """
        self._require_verified()
        problems = []
        unknown_keys = sorted(set(self._record) - TOP_LEVEL_KEYS)
        if unknown_keys:
            problems.append(
                "Provenance record has unknown top level properties: "
                + ", ".join(unknown_keys)
            )
        return problems + validation.record_problems(self._verified)

    def find_step(self, required_values):
        steps = self.filter_steps(required_values)
        if len(steps) == 0:
            raise ProvenanceError(f"No step matches required values {required_values}")
        if len(steps) > 1:
            raise ProvenanceError(
                f"More than one step matches required values {required_values}"
            )
        return steps[0]

    def require_signer(self, step_id, *, member=None, application=None, role=None):
        """Check who signed a step and return the step.

        Raises VerificationError unless the step was signed by a certificate with
        the given member URL, application URL and role. Arguments left as None
        are not checked.
        """
        step = self.find_step({"id": step_id})
        signed = step["_signature"]["signed"]
        problems = []
        if member is not None and signed["member"] != member:
            problems.append(f"signed by member {signed['member']}, expected {member}")
        if application is not None and signed["application"] != application:
            problems.append(
                f"signed by application {signed['application']}, expected {application}"
            )
        if role is not None and role not in signed["roles"]:
            problems.append(f"signer does not have role {role}")
        if problems:
            raise VerificationError(f"Step {step_id} " + "; ".join(problems))
        return step

    def filter_steps(self, required_values):
        self._require_verified()
        return list(
            filter(
                lambda s: self._filter_step_contains(s, required_values), self._verified
            )
        )

    def _filter_step_contains(self, step, required_values):
        if isinstance(required_values, dict):
            # If required_values is a dict, ensure step is a dict and contains all keys/values of required_values
            if not isinstance(step, dict):
                return False
            for key, value in required_values.items():
                if key not in step or not self._filter_step_contains(step[key], value):
                    return False
            return True
        elif isinstance(required_values, list):
            # If required_values is a list, ensure step is a list and contains all elements of required_values
            if not isinstance(step, list):
                return False
            for item in required_values:
                if not any(self._filter_step_contains(x, item) for x in step):
                    return False
            return True
        else:
            # If required_values is a primitive, ensure it matches the value in step
            return step == required_values

    def sign(self, signer):
        output = []
        certificates = {}
        if self._record is not None:
            if "certificates" in self._record:
                certificates.update(self._record["certificates"])
            output.append(self._record["steps"])  # signed and encoded
        for r in self._additional_records:
            if "certificates" in r:
                certificates.update(r["certificates"])
            output.append(r["steps"])  # signed and encoded
        for s in self._additional_steps:
            output.append(self._encode_step(s))  # unencoded, not signed
        # Check the record before signing it
        origins = []
        all_steps = []
        self._gather_steps(output, origins, all_steps)
        self._check_before_signing(all_steps)
        serial = signer.serial()
        sign_timestamp = self._timestamp_now_iso8601()
        data_for_signing = self._data_for_signing(
            output, [str(CURRENT_CONTAINER_FORMAT_VERSION), serial, sign_timestamp]
        )
        signature = signer.sign(data_for_signing.encode("utf-8"))
        output.append(
            [
                CURRENT_CONTAINER_FORMAT_VERSION,
                serial,
                sign_timestamp,
                base64.urlsafe_b64encode(signature).decode("utf-8"),
            ]
        )
        if serial not in certificates:
            certs_for_record = signer.certificates_for_record()
            if certs_for_record is not None:
                # Represent path as [pem encoded cert, serials of issuer chain ...]
                first_cert, *other_certs = certs_for_record
                cert_path = [
                    first_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                ]
                cert_path.extend(list(map(lambda c: str(c.serial_number), other_certs)))
                certificates[serial] = cert_path
                for c in other_certs:
                    certificates[str(c.serial_number)] = [
                        c.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                    ]
        encoded = {
            "ib1:provenance": self.trust_framework,
            "origins": origins,
            "steps": copy.deepcopy(output),
        }
        if certificates:
            encoded["certificates"] = certificates
        return Record(self.trust_framework, encoded)

    def _gather_steps(self, data, origins, steps):
        """Decode the steps in step list data (without its signature element)."""
        for e in data:
            if not isinstance(e, str):
                self._gather_steps(e[:-1], origins, steps)
            else:
                decoded_step = self._decode_step(e)
                steps.append(decoded_step)
                if decoded_step.get("type") == "origin":
                    origins.append(decoded_step.get("id"))

    def _check_before_signing(self, all_steps):
        # Only the steps added by this signer are checked in detail. Steps in
        # included records were signed by other participants and can't be changed.
        duplicates = self._duplicate_ids(all_steps)
        if duplicates:
            raise ValidationError(
                "Step ids are used more than once, was the same record added twice? "
                + ", ".join(duplicates)
            )
        if not any(s.get("type") == "origin" for s in all_steps):
            raise ValidationError(
                "A Provenance record must contain at least one origin step"
            )
        steps_by_id = {s.get("id"): s for s in all_steps}
        problems = []
        for step in self._additional_steps:
            problems.extend(validation.reference_problems(step, steps_by_id))
        if problems:
            raise ValidationError("; ".join(problems))

    def _encode_step(self, step):
        return base64.urlsafe_b64encode(
            json.dumps(step, separators=(",", ":")).encode("utf-8")
        ).decode("utf-8")

    def _data_for_signing(self, data, additional=None, is_root=True):
        gather = []
        if is_root:
            gather.append(self.trust_framework)
        for e in data:
            if isinstance(e, str):
                gather.append(e)
            elif isinstance(e, int):
                gather.append(str(e))
            else:
                gather.append("%")
                gather.append(self._data_for_signing(e, None, False))
                gather.append("&")
        if additional is not None:
            gather.extend(additional)
        return ".".join(gather)

    def encoded(self):  # TODO name
        self._require_signed()
        return self._record

    def decoded(self):  # TODO name
        self._require_verified()
        return copy.deepcopy(self._verified)

    def _require_signed(self):
        if not self._signed:
            raise ProvenanceError(
                "Record is not signed, call sign() and use returned object"
            )

    def _require_verified(self):
        if not (self._signed and (self._verified is not None)):
            raise ProvenanceError("Record is not verified, call verify() first")

    def _timestamp_now_iso8601(self):
        return (
            datetime.datetime.now(datetime.UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    def to_graphviz(self):
        self._require_verified()
        signers = {}
        dot = ["digraph ProvenanceRecord {"]
        for s in self._verified:
            id = s["id"]
            shape = "box"
            match s["type"]:
                case "permission":
                    shape = "invhouse"
                case "origin":
                    shape = "diamond"
                case "transfer":
                    dot.append('  "' + s["of"] + '" -> "' + id + '" [label=of];')
                case "receipt":
                    shape = "box3d"
                    dot.append(
                        '  "' + s["transfer"] + '" -> "' + id + '" [label=transfer];'
                    )
                case "process":
                    shape = "parallelogram"
            for key in ["inputs", "permissions"]:
                for i in s.get(key, []):
                    dot.append('  "' + i + '" -> "' + id + '" [label=' + key + "];")
            dot.append(
                '  "'
                + id
                + '" [shape='
                + shape
                + ',label="'
                + s["type"]
                + "\\n"
                + id
                + '"];'
            )
            signer = s["_signature"]["signed"]["name"]
            if signer not in signers:
                signers[signer] = []
            signers[signer].append(id)
        index = 0
        for signer in signers:
            dot.append("  subgraph cluster_" + str(index) + " {")
            index += 1
            dot.append("    graph[style=dashed];")
            dot.append('    label = "' + signer + '";')
            for i in signers[signer]:
                dot.append('    "' + i + '";')
            dot.append("  }")
        dot.append("}")
        return "\n".join(dot)
