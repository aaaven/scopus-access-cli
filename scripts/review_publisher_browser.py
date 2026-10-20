#!/usr/bin/env python3
"""Compatibility entry point; implementation ships in the installable package."""
from scopus_access import publisher_review as _implementation
# Include private compatibility helpers used by existing offline callers.
globals().update({name: value for name, value in vars(_implementation).items()
                  if not name.startswith('__')})
if __name__ == '__main__':
    raise SystemExit(_implementation.main())
