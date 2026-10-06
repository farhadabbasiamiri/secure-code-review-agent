import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ["SCRA_DISABLE_LOGS"] = "1"
os.environ["SCRA_OFFLINE"] = "1"
os.environ.setdefault("SCRA_LLM", "mock")

SAMPLES = ROOT / "data" / "samples"


@pytest.fixture
def sample():
    return lambda name: (SAMPLES / name).read_bytes()
