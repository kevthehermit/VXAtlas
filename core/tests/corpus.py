"""Access to the optional real-image corpus and its ground-truth records."""

import json
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GROUND_TRUTH = json.loads((REPO / "testdata" / "ground_truth.json").read_text())["images"]
GROUND_TRUTH_BY_FILE = {t["file"]: t for t in GROUND_TRUTH}


def corpus_path(name: str) -> Path:
    """Path of a corpus image, or skip the test if the corpus is not mounted."""
    root = os.environ.get("VXATLAS_SAMPLES", "")
    if not root:
        pytest.skip("VXATLAS_SAMPLES is not set; corpus image %s not available" % name)
    for candidate in (Path(root) / "corpus" / name, Path(root) / name):
        if candidate.is_file():
            return candidate
    pytest.skip("corpus image %s not found under VXATLAS_SAMPLES=%s" % (name, root))
