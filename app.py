"""Entry point for `python app.py` and Hugging Face Spaces (which run app.py from the repo root)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from scra.app import main  # noqa: E402

if __name__ == "__main__":
    main()
