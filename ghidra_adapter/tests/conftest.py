import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "core" / "tests"))  # synth.py and corpus.py helpers

@pytest.fixture(scope="session")
def ghidra():
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("GHIDRA_INSTALL_DIR is not set; run these tests with "
                    "'docker compose run --rm test'")
    import pyghidra
    pyghidra.start()
    return pyghidra


@pytest.fixture(scope="session")
def project(ghidra, tmp_path_factory):
    proj = ghidra.open_project(tmp_path_factory.mktemp("ghidra"), "vxatlas_tests", create=True)
    yield proj
    proj.close()
