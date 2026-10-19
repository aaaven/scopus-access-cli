#!/usr/bin/env python3
"""Independent DOI probe launcher; uses the same validated engine as the CLI.

Install the package or set PYTHONPATH=src. No credentials are read.
"""
from scopus_access.enrichment import main

if __name__ == '__main__':
    raise SystemExit(main())
