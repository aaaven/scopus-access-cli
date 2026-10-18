#!/usr/bin/env python3
"""Run the full test suite while making every network attempt a hard failure."""

import socket
import os
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


def main() -> int:
    attempts = []

    repository_root = Path(__file__).resolve().parent.parent
    source_root = Path(os.environ.get("SCOPUS_TEST_PACKAGE_ROOT", str(repository_root / "src")))
    sys.path.insert(0, str(source_root))

    def blocked(*args, **kwargs):
        # Count only.  Never retain a destination, hostname, or other caller
        # value that could contain sensitive task material.
        attempts.append(1)
        raise AssertionError("network access is forbidden in the offline test suite")

    guards = [
        (socket, "create_connection", (("guard.invalid", 443),)),
        (socket.socket, "connect", (None, ("127.0.0.1", 9))),
        (socket.socket, "connect_ex", (None, ("127.0.0.1", 9))),
        (socket.socket, "sendto", (None, b"", ("127.0.0.1", 9))),
        (socket, "getaddrinfo", ("guard.invalid", 443)),
        (socket, "gethostbyname", ("guard.invalid",)),
        (socket, "gethostbyname_ex", ("guard.invalid",)),
        (socket, "gethostbyaddr", ("127.0.0.1",)),
        (socket, "getnameinfo", (("127.0.0.1", 9), 0)),
    ]
    if hasattr(socket.socket, "sendmsg"):
        guards.append(
            (socket.socket, "sendmsg", (None, [b""], [], 0, ("127.0.0.1", 9)))
        )

    with ExitStack() as stack:
        for owner, name, _ in guards:
            stack.enter_context(mock.patch.object(owner, name, side_effect=blocked))

        # Prove every installed guard is active before importing any test
        # module.  Expected self-probes are then discarded; any later entry is
        # a real test-suite network attempt and makes the run fail.
        for owner, name, arguments in guards:
            try:
                getattr(owner, name)(*arguments)
            except AssertionError:
                pass
            else:
                sys.stderr.write("OFFLINE NETWORK GUARD: self-check failed\n")
                return 1
        if len(attempts) != len(guards):
            sys.stderr.write("OFFLINE NETWORK GUARD: self-check incomplete\n")
            return 1
        attempts.clear()

        # Discovery imports every test module, so the guard must already be
        # active before discovery begins.
        suite = unittest.defaultTestLoader.discover(
            str(repository_root / "tests"), pattern="test_*.py"
        )
        result = unittest.TextTestRunner(verbosity=2).run(suite)

    if attempts:
        sys.stderr.write("OFFLINE NETWORK GUARD: blocked %d attempt(s)\n" % len(attempts))
        return 1
    sys.stderr.write("OFFLINE NETWORK GUARD: zero connection attempts\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
