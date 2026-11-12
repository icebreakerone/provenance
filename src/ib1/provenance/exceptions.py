class ProvenanceError(Exception):
    """Base class for errors raised by this library."""


class ValidationError(ProvenanceError):
    """A record or step does not follow the Provenance Records specification."""


class VerificationError(ProvenanceError):
    """A signed record could not be verified."""


class CertificateError(ProvenanceError):
    """A certificate is missing or does not have the expected contents."""


class CertificateNotFoundError(CertificateError, KeyError):
    """A certificate serial number is not available.

    Also a KeyError, which this library raised before CertificateError existed.
    """

    def __str__(self):
        # KeyError quotes its message, show it as plain text instead
        return str(self.args[0]) if self.args else ""
