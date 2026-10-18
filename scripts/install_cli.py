#!/usr/bin/env python3
"""One-time source bootstrap; project initialization remains a CLI command."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from scopus_access.installer import main

if __name__ == "__main__":
    raise SystemExit(main())
