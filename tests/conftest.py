import pytest

from specimen.lab_fixtures import write_fixtures


@pytest.fixture(scope="session")
def fx(tmp_path_factory):
    return write_fixtures(tmp_path_factory.mktemp("lab"))
