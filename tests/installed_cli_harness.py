"""Execute a real installed console entry with process-local offline doubles."""
import json
import os
import runpy
import shutil
import socket
import sys
import time
import dataclasses
from urllib.parse import parse_qs, urlsplit
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
    if os.environ.get('SCOPUS_TEST_LEGACY_BALANCE_PAUSE')=='1':
        from scopus_access import ledger, quota
        current_evaluate=quota.evaluate_headers
        def legacy_evaluate(headers, observed, previous=None):
            value=current_evaluate(headers,observed,previous)
            if (value.valid and previous is not None and value.reset_at_utc==previous.reset_at_utc
                    and previous.effective_remaining is not None and value.remaining>previous.effective_remaining):
                return dataclasses.replace(value,valid=False,reason_code='RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING',
                    limit=None,remaining=None,reset_at_utc=None,window_id_changed=False)
            return value
        stack.enter_context(mock.patch.object(ledger,'evaluate_headers',side_effect=legacy_evaluate))

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
            params=parse_qs(urlsplit(request.url).query)
            start=int(params.get('start',['0'])[0]); count=int(params.get('count',['1'])[0])
            total=int(os.environ.get('SCOPUS_TEST_TOTAL','1'))
            body = {"search-results": {"entry": [{"dc:identifier": "SYNTHETIC-INSTALLED-ID-%d"%index} for index in range(start,min(total,start+count))],
                                      "opensearch:totalResults": str(total), "opensearch:startIndex": str(start)}}
            return TransportResponse(status=200, headers={} if os.environ.get('SCOPUS_TEST_QUOTA_MISSING')=='1' else {
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
            if os.environ.get("SCOPUS_TEST_TERMINAL_RUN") == "fail_open":
                from scopus_access.terminal_init import TerminalInitError
                raise TerminalInitError("TERMINAL_OPEN_FAILED")
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                terminal_run.child_main(shlex.split(command)[-6:])
        stack.enter_context(mock.patch.object(terminal_run, "_launch", run_mock_terminal))

    stack.enter_context(mock.patch.object(cli, "MacOSKeychainSecretProvider", Provider))
    stack.enter_context(mock.patch.object(cli, "UrllibTransport", Transport))
    if os.environ.get("SCOPUS_TEST_USER_DIRECTORY"):
        stack.enter_context(mock.patch.object(Path, "home", return_value=Path(os.environ["SCOPUS_TEST_USER_DIRECTORY"])))
    if os.environ.get('SCOPUS_TEST_ENRICH')=='1':
        from scopus_access import enrichment
        class PublicTransport:
            def send(self,provider,doi,*,permit):
                permit.claim(provider,doi)
                counter=os.environ.get('SCOPUS_TEST_ENRICH_COUNTER')
                if counter:
                    fd=os.open(counter,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
                    try:os.write(fd,b'sent\n')
                    finally:os.close(fd)
                if provider=='crossref':
                    payload={'message':{'DOI':doi,'title':['SYNTHETIC ENRICH TITLE'],'type':'journal-article',
                        'abstract':'<p>SYNTHETIC ENRICH ABSTRACT</p>','author':[{'name':'SYNTHETIC AUTHOR'}],
                        'reference':[{'DOI':'10.1234/reference'}],'reference-count':1}}
                else:
                    payload={'doi':'https://doi.org/'+doi,'title':'SYNTHETIC ENRICH TITLE',
                        'authorships':[{'raw_author_name':'SYNTHETIC AUTHOR'}],
                        'abstract_inverted_index':{'SYNTHETIC':[0],'ABSTRACT':[1]}}
                return 200,{},json.dumps(payload).encode()
        stack.enter_context(mock.patch.object(enrichment,'_PublicTransport',PublicTransport))
    if os.environ.get('SCOPUS_TEST_ZOTERO') == '1':
        from scopus_access import zotero, zotero_local

        class ZoteroTransport:
            """In-process HTTP service double; only synthetic restricted state."""
            def __init__(self):
                assert os.environ.get('SCOPUS_TEST_LOCAL_ONLY') != '1', 'unexpected Zotero transport'

            def request(self, method, path, headers, body):
                assert headers['Zotero-API-Key'] == secret.decode()
                assert headers['Zotero-API-Version'] == '3'
                state_path = Path(os.environ['SCOPUS_TEST_ZOTERO_STATE'])
                state = json.loads(state_path.read_text())
                response_headers = {'Last-Modified-Version': str(state['version']),
                                    'Total-Results': str(len(state['items'])), 'Zotero-API-Version': '3'}
                parsed = urlsplit(path)
                params = parse_qs(parsed.query)
                if method == 'GET' and parsed.path == '/keys/current':
                    value = {'userID': 42, 'access': {'groups': {'123': {'library': True, 'write': True}}}}
                elif method == 'GET' and parsed.path == '/groups/123':
                    value = {'id': 123, 'data': {'name': 'SYNTHETIC OPTIONAL GROUP'}}
                elif method == 'GET' and parsed.path == '/items/new':
                    value = {name: '' for name in ('title', 'extra', 'DOI', 'date', 'publicationTitle', 'abstractNote')}
                    value.update(itemType=params['itemType'][0], creators=[], tags=[], collections=[], relations={})
                elif method == 'GET' and parsed.path == '/groups/123/items':
                    if params.get('format') == ['versions']:
                        value = {row['key']: row['version'] for row in state['items']}
                    else:
                        start = int(params.get('start', ['0'])[0])
                        value = state['items'][start:start + 100]
                elif method == 'POST' and parsed.path == '/groups/123/items':
                    assert headers['If-Unmodified-Since-Version'] == str(state['version'])
                    submitted = json.loads(body)
                    assert 1 <= len(submitted) <= 50
                    state['version'] += 1
                    value = {'successful': {}, 'unchanged': {}, 'failed': {}}
                    for index, item in enumerate(submitted):
                        item = dict(item, version=state['version'])
                        row = {'key': item['key'], 'version': state['version'],
                               'library': {'id': 123, 'type': 'group'}, 'data': item}
                        state['items'] = [old for old in state['items'] if old['key'] != row['key']] + [row]
                        value['successful'][str(index)] = row
                    state_path.write_text(json.dumps(state))
                    response_headers['Last-Modified-Version'] = str(state['version'])
                    response_headers['Total-Results'] = str(len(state['items']))
                    counter = os.environ.get('SCOPUS_TEST_ZOTERO_COUNTER')
                    if counter:
                        with open(counter, 'ab') as stream:
                            stream.write(b'write\n')
                else:
                    raise AssertionError('unexpected synthetic Zotero request')
                return 200, response_headers, json.dumps(value).encode()

        stack.enter_context(mock.patch.object(zotero_local, 'MacOSKeychainWriter', Writer))
        stack.enter_context(mock.patch.object(zotero_local, 'prompt_zotero_key', lambda: secrets.SecretValue(secret)))
        stack.enter_context(mock.patch.object(zotero, 'MacOSKeychainSecretProvider', Provider))
        stack.enter_context(mock.patch.object(zotero, 'HTTPSTransport', ZoteroTransport))
    executable = shutil.which(sys.argv[1])
    assert executable and Path(executable).resolve().parent == (Path(sys.prefix) / "bin").resolve()
    sys.argv = [executable] + sys.argv[2:]
    try:
        runpy.run_path(executable, run_name="__main__")
    finally:
        if attempts:
            raise AssertionError("installed CLI attempted socket access")
