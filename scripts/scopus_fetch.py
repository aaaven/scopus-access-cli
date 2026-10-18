#!/usr/bin/env python3
"""Source-checkout wrapper for the reusable scopus-fetch command."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from scopus_access.fetch import main


if __name__ == "__main__":
    raise SystemExit(main())
