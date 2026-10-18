"""Execute a real installed console entry with process-local offline doubles."""
import json
import os
import runpy
import shutil
import socket
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


attempts = []


def blocked(*args, **kwargs):
    attempts.append(1)
    raise AssertionError("installed CLI tests forbid all socket access")


with ExitStack() as stack:
    for owner, name in [(socket, name) for name in (
            "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex",
            "gethostbyaddr", "getnameinfo")] + [(socket.socket, name) for name in (
            "connect", "connect_ex", "sendto", "sendmsg") if hasattr(socket.socket, name)]:
        stack.enter_context(mock.patch.object(owner, name, side_effect=blocked))
    # Import only after guards are active. -I excludes the source checkout and
    # PYTHONPATH, and the assertion verifies the actual installed module origin.
    import scopus_access
    from scopus_access import cli, secrets
    from scopus_access.client import TransportResponse
    assert Path(scopus_access.__file__).is_relative_to(Path(sys.prefix))
    secret = b"SYNTHETIC_INSTALLED_CLI_CREDENTIAL"

    class Writer:
        def __init__(self, *args, **kwargs):
            pass

        def contains_api_key(self, alias):
            return True

        def add_api_key(self, alias, label, value):
            assert value.reveal().encode() == secret

    class Provider:
        def __init__(self, *args, **kwargs):
            assert os.environ.get("SCOPUS_TEST_LOCAL_ONLY") != "1", "unexpected credential provider"

        def get_api_key(self, alias):
            if os.environ.get("SCOPUS_TEST_TERMINAL_RUN"):
                assert sys.stdin.isatty(), "credential read must happen in Terminal child"
            if os.environ.get("SCOPUS_TEST_PROVIDER_ERROR") == "1":
                raise secrets.SecretProviderError(reason="interaction_not_allowed", stage="credential_read",
                                                  backend="macos_security_framework", system_error_code=-25308)
            return secrets.SecretValue(secret)

    class Transport:
        def __init__(self):
            assert os.environ.get("SCOPUS_TEST_LOCAL_ONLY") != "1", "unexpected transport"

        def send(self, request, *, wire_capability=None):
            assert request.headers["X-ELS-APIKey"] == secret.decode()
            if os.environ.get("SCOPUS_TEST_WIRE_COUNTER"):
                fd = os.open(os.environ["SCOPUS_TEST_WIRE_COUNTER"], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(fd, b"sent\n")
                finally:
                    os.close(fd)
                time.sleep(0.1)
            body = {"search-results": {"entry": [{"dc:identifier": "SYNTHETIC-INSTALLED-ID"}],
                                      "opensearch:totalResults": "1", "opensearch:startIndex": "0"}}
            return TransportResponse(status=200, headers={
                "X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99",
                "X-RateLimit-Reset": "4102444800",
            }, body=json.dumps(body).encode())

    stack.enter_context(mock.patch.object(secrets, "MacOSKeychainWriter", Writer))
    handoff_mode = os.environ.get("SCOPUS_TEST_TERMINAL_HANDOFF")
    def prompt():
        if handoff_mode and not sys.stdin.isatty():
            raise secrets.SecretProviderError(reason="interaction_not_allowed", stage="credential_prompt", backend="terminal_input")
        if handoff_mode == "cancel":
            raise secrets.SecretProviderError(reason="access_denied", stage="credential_prompt", backend="terminal_input")
        return secrets.SecretValue(secret)
    stack.enter_context(mock.patch.object(secrets, "prompt_api_key", prompt))
    if handoff_mode:
        import shlex
        from scopus_access import terminal_init
        stack.enter_context(mock.patch.object(Writer, "contains_api_key", lambda self, alias: False))
        def open_mock_terminal(command):
            if os.environ.get("SCOPUS_TEST_TERMINAL_COUNTER"):
                with open(os.environ["SCOPUS_TEST_TERMINAL_COUNTER"], "ab") as stream:
                    stream.write(b"opened\n")
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                terminal_init.child_main(shlex.split(command)[-4:])
        stack.enter_context(mock.patch.object(terminal_init, "_launch", open_mock_terminal))

    if os.environ.get("SCOPUS_TEST_TERMINAL_RUN"):
        import shlex
        from scopus_access import terminal_run
        def run_mock_terminal(command):
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                terminal_run.child_main(shlex.split(command)[-6:])
        stack.enter_context(mock.patch.object(terminal_run, "_launch", run_mock_terminal))

    stack.enter_context(mock.patch.object(cli, "MacOSKeychainSecretProvider", Provider))
    stack.enter_context(mock.patch.object(cli, "UrllibTransport", Transport))
    if os.environ.get("SCOPUS_TEST_USER_DIRECTORY"):
        stack.enter_context(mock.patch.object(Path, "home", return_value=Path(os.environ["SCOPUS_TEST_USER_DIRECTORY"])))
    executable = shutil.which(sys.argv[1])
    assert executable and Path(executable).resolve().parent == (Path(sys.prefix) / "bin").resolve()
    sys.argv = [executable] + sys.argv[2:]
    try:
        runpy.run_path(executable, run_name="__main__")
    finally:
        if attempts:
            raise AssertionError("installed CLI attempted socket access")
