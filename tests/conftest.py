import pytest

from ib1.provenance.certificates import (
    CertificatesProviderLocal,
    CertificatesProviderSelfContainedRecord,
)
from pki import PKI, SCHEME_URL


@pytest.fixture(scope="session")
def pki():
    return PKI()


@pytest.fixture(scope="session")
def edp(pki):
    return pki.member(
        "Smart Meter Reading Co",
        2876152,
        38936455,
        [f"{SCHEME_URL}/role/energy-data-provider"],
        123456,
    )


@pytest.fixture(scope="session")
def cap(pki):
    return pki.member(
        "Carbon Accounting Provider",
        81524,
        26241,
        [f"{SCHEME_URL}/role/carbon-accounting-provider"],
        98765,
    )


@pytest.fixture(scope="session")
def self_contained_provider(pki):
    return CertificatesProviderSelfContainedRecord(pki.root_pem)


@pytest.fixture
def local_provider(pki, edp, cap, tmp_path):
    pki.write_bundles(tmp_path, edp, cap)
    return CertificatesProviderLocal(pki.root_pem, str(tmp_path))
