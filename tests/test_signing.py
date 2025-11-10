import os
import tempfile
import pytest
from unittest.mock import Mock, patch
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ib1.provenance.signing import SignerInMemory, SignerFiles, SignerKMS
from ib1.provenance.certificates import CertificateProviderBase as CertificateProvider

# Test certificate (PEM format)
TEST_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDKTCCAtGgAwIBAgIDAeJAMAoGCCqGSM49BAMCMGsxCzAJBgNVBAYTAkdCMQ8w
DQYDVQQIDAZMb25kb24xHTAbBgNVBAoMFENvcmUgVHJ1c3QgRnJhbWV3b3JrMSww
KgYDVQQDDCNDb3JlIFRydXN0IEZyYW1ld29yayBTaWduaW5nIElzc3VlcjAeFw0y
NTAyMTIxMTQ5MjdaFw0yNjAyMTIxMTQ5MjdaMIGOMQswCQYDVQQGEwJHQjEPMA0G
A1UECAwGTG9uZG9uMTAwLgYDVQQKDCdIb25lc3QgRGF2ZSdzIEFjY3VyYXRlIE1l
dGVyIFJlYWRpbmcgQ28xPDA6BgNVBAMMM2h0dHBzOi8vZGlyZWN0b3J5LmNvcmUu
dHJ1c3QuaWIxLm9yZy9tZW1iZXIvMjg3NjE1MjBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABHX4Pgtv+P/GgzPTjHCJB5r6AUafOLrCe490VoNgOCani4bpiJHifqtr
kYZGrS54QFUHuAN6V1it/mEvfv6EftejggE+MIIBOjA+BgNVHREENzA1hjNodHRw
czovL2RpcmVjdG9yeS5jb3JlLnRydXN0LmliMS5vcmcvbWVtYmVyLzI4NzYxNTIw
XgYKKwYBBAGD5nkBAQRQME4MTGh0dHBzOi8vcmVnaXN0cnkuY29yZS50cnVzdC5p
YjEub3JnL3NjaGVtZS9wZXJzZXVzL3JvbGUvZW5lcmd5LWRhdGEtcHJvdmlkZXIw
WAYKKwYBBAGD5nkBAgRKDEhodHRwczovL2RpcmVjdG9yeS5jb3JlLnRydXN0Lmli
MS5vcmcvc2NoZW1lL3BlcnNldXMvYXBwbGljYXRpb24vMzg5MzY0NTUwHQYDVR0O
BBYEFHp7zhtA5U2MVWdkM8HbHcm9WcRvMB8GA1UdIwQYMBaAFC/vje0a/J/YK5c7
9+gFY8yYG0BmMAoGCCqGSM49BAMCA0YAMEMCIA126TTXg2cWwgz4Jxr2xMhU7nB0
SNAAbhyhwAu5DugcAh85WnyC0Vv9aulOC3Tutp9dydYZE9bG6ipxm90aScLk
-----END CERTIFICATE-----"""

# Test private key (PEM format)
TEST_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHX4Pgtv+P/GgzPTj
HCJB5r6AUafOLrCe490VoNgOCamhRANCAAR1+D4Lb/j/xoMz04xwiQea+gFGnzi6
wnuPdFaDYDgmp4uG6YiR4n6ra5GGRq0ueEBVB7gDeldYrf5hL37+hH7X
-----END PRIVATE KEY-----"""


class TestSignerInMemory:
    """Test cases for SignerInMemory class"""

    def setup_method(self):
        """Set up test fixtures"""
        # Create a mock certificate provider
        self.certificate_provider = Mock(spec=CertificateProvider)
        self.certificate_provider.policy_include_certificates_in_record = True

        # Load test certificate
        self.certificate = x509.load_pem_x509_certificate(TEST_CERT_PEM.encode())
        self.certificates = [self.certificate]

        # Load test private key
        self.private_key = serialization.load_pem_private_key(
            TEST_KEY_PEM.encode(), password=None
        )

    def test_signer_in_memory_initialization(self):
        """Test SignerInMemory initialization"""
        signer = SignerInMemory(
            self.certificate_provider, self.certificates, self.private_key
        )

        assert signer._certificate_provider == self.certificate_provider
        assert signer._certificates == self.certificates
        assert signer._private_key == self.private_key

    def test_signer_in_memory_serial(self):
        """Test serial number extraction"""
        signer = SignerInMemory(
            self.certificate_provider, self.certificates, self.private_key
        )

        serial = signer.serial()
        assert isinstance(serial, str)
        assert serial == str(self.certificate.serial_number)

    def test_certificates_for_record_included(self):
        """Test certificates_for_record when policy includes certificates"""
        signer = SignerInMemory(
            self.certificate_provider, self.certificates, self.private_key
        )

        result = signer.certificates_for_record()
        assert result == self.certificates.copy()

    def test_certificates_for_record_not_included(self):
        """Test certificates_for_record when policy excludes certificates"""
        self.certificate_provider.policy_include_certificates_in_record = False
        signer = SignerInMemory(
            self.certificate_provider, self.certificates, self.private_key
        )

        result = signer.certificates_for_record()
        assert result is None

    def test_sign_data(self):
        """Test signing data"""
        signer = SignerInMemory(
            self.certificate_provider, self.certificates, self.private_key
        )

        test_data = b"test data to sign"
        signature = signer.sign(test_data)

        assert isinstance(signature, bytes)
        assert len(signature) > 0


class TestSignerFiles:
    """Test cases for SignerFiles class"""

    def setup_method(self):
        """Set up test fixtures"""
        # Create a mock certificate provider
        self.certificate_provider = Mock(spec=CertificateProvider)
        self.certificate_provider.policy_include_certificates_in_record = True

    def test_signer_files_initialization(self):
        """Test SignerFiles initialization with temporary files"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as cert_file:
            cert_file.write(TEST_CERT_PEM)
            cert_file_path = cert_file.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as key_file:
            key_file.write(TEST_KEY_PEM)
            key_file_path = key_file.name

        try:
            signer = SignerFiles(
                self.certificate_provider, cert_file_path, key_file_path
            )

            assert signer._certificate_provider == self.certificate_provider
            assert len(signer._certificates) == 1
            assert signer._private_key is not None

            # Test that it inherits from SignerInMemory
            assert isinstance(signer, SignerInMemory)

        finally:
            # Clean up temporary files
            os.unlink(cert_file_path)
            os.unlink(key_file_path)

    def test_signer_files_missing_certificate_file(self):
        """Test SignerFiles with missing certificate file"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as key_file:
            key_file.write(TEST_KEY_PEM)
            key_file_path = key_file.name

        try:
            with pytest.raises(FileNotFoundError):
                SignerFiles(
                    self.certificate_provider, "nonexistent_cert.pem", key_file_path
                )
        finally:
            os.unlink(key_file_path)

    def test_signer_files_missing_key_file(self):
        """Test SignerFiles with missing key file"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as cert_file:
            cert_file.write(TEST_CERT_PEM)
            cert_file_path = cert_file.name

        try:
            with pytest.raises(FileNotFoundError):
                SignerFiles(
                    self.certificate_provider, cert_file_path, "nonexistent_key.pem"
                )
        finally:
            os.unlink(cert_file_path)


class TestSignerKMS:
    """Test cases for SignerKMS class"""

    def setup_method(self):
        """Set up test fixtures"""
        # Create a mock certificate provider
        self.certificate_provider = Mock(spec=CertificateProvider)
        self.certificate_provider.policy_include_certificates_in_record = True

        # Load test certificate
        self.certificate = x509.load_pem_x509_certificate(TEST_CERT_PEM.encode())
        self.certificates = [self.certificate]

        # Mock KMS client
        self.mock_kms_client = Mock()
        self.key_id = "test-key-id"

    def test_signer_kms_initialization_with_boto3(self):
        """Test SignerKMS initialization when boto3 is available"""
        # Mock importlib.util.find_spec to return a spec (indicating boto3 is available)
        with patch("importlib.util.find_spec", return_value=Mock()):
            signer = SignerKMS(
                self.certificate_provider,
                self.certificates,
                self.mock_kms_client,
                self.key_id,
            )

            assert signer._certificate_provider == self.certificate_provider
            assert signer._certificates == self.certificates
            assert signer._kms_client == self.mock_kms_client
            assert signer._key_id == self.key_id

            # Test that it inherits from SignerInMemory
            assert isinstance(signer, SignerInMemory)

    def test_signer_kms_initialization_without_boto3(self):
        """Test SignerKMS initialization when boto3 is not available"""
        # Mock importlib.util.find_spec to return None (indicating boto3 is not available)
        with patch("importlib.util.find_spec", return_value=None):
            with pytest.raises(ImportError, match="boto3 is required for SignerKMS"):
                SignerKMS(
                    self.certificate_provider,
                    self.certificates,
                    self.mock_kms_client,
                    self.key_id,
                )

    def test_signer_kms_missing_kms_client(self):
        """Test SignerKMS with None kms_client"""
        with patch("importlib.util.find_spec", return_value=Mock()):
            with pytest.raises(
                ValueError, match="kms_client and key_id are required for SignerKMS"
            ):
                SignerKMS(
                    self.certificate_provider, self.certificates, None, self.key_id
                )

    def test_signer_kms_missing_key_id(self):
        """Test SignerKMS with None key_id"""
        with patch("importlib.util.find_spec", return_value=Mock()):
            with pytest.raises(
                ValueError, match="kms_client and key_id are required for SignerKMS"
            ):
                SignerKMS(
                    self.certificate_provider,
                    self.certificates,
                    self.mock_kms_client,
                    None,
                )

    def test_signer_kms_sign(self):
        """Test SignerKMS sign method"""
        import hashlib
        with patch("importlib.util.find_spec", return_value=Mock()):
            signer = SignerKMS(
                self.certificate_provider,
                self.certificates,
                self.mock_kms_client,
                self.key_id,
            )

            # Mock the KMS client response
            mock_response = {
                "Signature": b"mock_signature_data",
                "KeyId": self.key_id,
                "SigningAlgorithm": "ECDSA_SHA_256",
            }
            self.mock_kms_client.sign.return_value = mock_response

            test_data = b"test data to sign"
            result = signer.sign(test_data)

            # Calculate expected digest (SHA-256 hash of test_data)
            expected_digest = hashlib.sha256(test_data).digest()

            # Verify KMS client was called correctly with digest and MessageType="DIGEST"
            self.mock_kms_client.sign.assert_called_once_with(
                KeyId=self.key_id,
                Message=expected_digest,
                MessageType="DIGEST",
                SigningAlgorithm="ECDSA_SHA_256",
            )

            # Verify result
            assert result == mock_response["Signature"]

    def test_signer_kms_inherits_methods(self):
        """Test that SignerKMS inherits methods from SignerInMemory"""
        with patch("importlib.util.find_spec", return_value=Mock()):
            signer = SignerKMS(
                self.certificate_provider,
                self.certificates,
                self.mock_kms_client,
                self.key_id,
            )

            # Test inherited methods
            serial = signer.serial()
            assert isinstance(serial, str)

            certificates = signer.certificates_for_record()
            assert certificates == self.certificates.copy()


class TestSignerIntegration:
    """Integration tests for all signer classes"""

    def test_all_signers_have_common_interface(self):
        """Test that all signer classes have the same interface"""
        certificate_provider = Mock(spec=CertificateProvider)
        certificate_provider.policy_include_certificates_in_record = True

        certificate = x509.load_pem_x509_certificate(TEST_CERT_PEM.encode())
        certificates = [certificate]
        private_key = serialization.load_pem_private_key(
            TEST_KEY_PEM.encode(), password=None
        )

        # Test SignerInMemory
        signer_memory = SignerInMemory(certificate_provider, certificates, private_key)

        # Test SignerFiles with temporary files
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as cert_file:
            cert_file.write(TEST_CERT_PEM)
            cert_file_path = cert_file.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as key_file:
            key_file.write(TEST_KEY_PEM)
            key_file_path = key_file.name

        try:
            signer_files = SignerFiles(
                certificate_provider, cert_file_path, key_file_path
            )

            # Test SignerKMS
            mock_kms_client = Mock()
            with patch("importlib.util.find_spec", return_value=Mock()):
                signer_kms = SignerKMS(
                    certificate_provider, certificates, mock_kms_client, "test-key"
                )

            # All signers should have these methods
            common_methods = ["serial", "certificates_for_record", "sign"]
            for signer in [signer_memory, signer_files, signer_kms]:
                for method in common_methods:
                    assert hasattr(
                        signer, method
                    ), f"{type(signer).__name__} missing {method}"
                    assert callable(
                        getattr(signer, method)
                    ), f"{type(signer).__name__}.{method} is not callable"

        finally:
            # Clean up temporary files
            os.unlink(cert_file_path)
            os.unlink(key_file_path)
