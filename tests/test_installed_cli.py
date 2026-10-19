"""Process acceptance against a wheel installed outside the source checkout.

Set SCOPUS_TEST_INSTALLED_PYTHON to an isolated installation's Python. Every
console execution uses installed_cli_harness.py to mock credentials/transport
and enforce socket guards in that child before importing the package.
"""
import json
import os
import subprocess
import tempfile
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


class InstalledCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("SCOPUS_TEST_INSTALLED_PYTHON")
        if not value:
            raise unittest.SkipTest("requires an offline-installed wheel environment")
        cls.python = Path(value).absolute()
        cls.bin = Path(os.environ.get("SCOPUS_TEST_INSTALLED_BIN", str(cls.python.parent)))
        cls.harness = Path(__file__).with_name("installed_cli_harness.py")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "survey"
        self.root.mkdir()

    def invoke(self, cwd, *arguments, entry="scopus-access", local=True, environment=None):
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.defpath,
                   PYTHONDONTWRITEBYTECODE="1", SCOPUS_TEST_LOCAL_ONLY="1" if local else "0")
        if environment:
            env.update(environment)
        # A deliberately unusable PYTHONPATH proves -I doesn't borrow source.
        env["PYTHONPATH"] = str(self.base / "missing-source")
        result = subprocess.run([str(self.python), "-I", str(self.harness), entry] + list(arguments),
                                cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=False)
        for content in (result.stdout, result.stderr):
            self.assertNotIn(b"SYNTHETIC_INSTALLED_CLI_CREDENTIAL", content)
            self.assertNotIn(b"SYNTHETIC_INSTALLED_QUERY", content)
        rows = [json.loads(line) for line in result.stdout.decode().splitlines()]
        return result.returncode, rows

    def initialize(self, root=None):
        code, rows = self.invoke(root or self.root, "init")
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["quota_state"], "UNVERIFIED")
        self.assertEqual(rows[0]["network_calls"], 0)
        return rows[0]

    def query(self):
        path = self.root / "restricted_metadata/query.txt"
        path.write_text("SYNTHETIC_INSTALLED_QUERY")
        return path

    def test_installed_agent_init_handoff_returns_result_without_key_or_shell_copy(self):
        counter = self.base / "terminal-windows"
        environment = {"SCOPUS_TEST_TERMINAL_HANDOFF": "success", "SCOPUS_TEST_TERMINAL_COUNTER": str(counter)}
        code, rows = self.invoke(self.root, "init", environment=environment)
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["status"], "initialized")
        self.assertTrue(rows[0]["credential_written"])
        self.assertEqual(rows[0]["quota_state"], "UNVERIFIED")
        self.assertEqual((rows[0]["network_calls"], rows[0]["secret_reads"]), (0, 0))
        code, reused = self.invoke(self.root, "init", environment=environment)
        self.assertEqual((code, reused[0]["status"]), (0, "reused"))
        self.assertEqual(counter.read_bytes(), b"opened\n")
        self.assertEqual(rows[0]["project_id"], reused[0]["project_id"])
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SYNTHETIC_INSTALLED_CLI_CREDENTIAL", path.read_bytes())

    def test_installed_agent_cancel_preserves_binding_and_can_retry_handoff(self):
        code, rows = self.invoke(self.root, "init", environment={"SCOPUS_TEST_TERMINAL_HANDOFF": "cancel"})
        self.assertEqual((code, rows[0]["provider_reason"]), (4, "access_denied"))
        binding = json.loads((self.root / ".scopus-access/policy.json").read_text())["project_binding"]
        self.assertEqual(binding["state"], "pending")
        code, rows = self.invoke(self.root, "init", environment={"SCOPUS_TEST_TERMINAL_HANDOFF": "success"})
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["project_id"], binding["project_id"])
        self.assertEqual(rows[0]["quota_state"], "UNVERIFIED")

    def test_installed_terminal_execute_and_unused_preflight_resume_keep_original_budget(self):
        self.initialize()
        query = self.query()
        code, rows = self.invoke(self.root, "check", "--query-file", str(query))
        self.assertEqual(code, 0, rows)
        preview = rows[0]["run_info_path"]
        code, rows = self.invoke(self.root, "execute", "--run-info", preview, "--execute-live", "--terminal",
                                 local=False, environment={"SCOPUS_TEST_TERMINAL_RUN": "1", "SCOPUS_TEST_PROVIDER_ERROR": "1"})
        self.assertEqual(code, 6, rows)
        run_info = rows[0]["run_info_path"]
        original = Path(run_info).read_bytes()
        self.assertEqual(rows[-1]["requests_attempted"], 0)
        code, rows = self.invoke(self.root, "resume", "--run-info", run_info, "--execute-live", "--terminal",
                                 local=False, environment={"SCOPUS_TEST_TERMINAL_RUN": "1"})
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[-1]["requests_attempted"], 1)
        self.assertEqual(Path(run_info).read_bytes(), original)
        code, rows = self.invoke(self.root, "resume", "--run-info", run_info, "--execute-live", "--terminal",
                                 environment={"SCOPUS_TEST_TERMINAL_RUN": "1"})
        self.assertEqual(code, 2, rows)
        self.assertEqual(rows[-1]["code"], "PREFLIGHT_RESUME_DENIED")
        code, rows = self.invoke(self.root, "usage")
        self.assertEqual((code, rows[0]["requests_attempted"]), (0, 1))

    def test_installed_console_outside_source_root_and_three_subdirectories_share_state(self):
        first = self.initialize()
        query = self.query()
        child = self.root / "a/b/c"
        child.mkdir(parents=True)
        for directory in (self.root, self.root / "a", child):
            code, rows = self.invoke(directory, "search", "--query-file", str(query))
            self.assertEqual(code, 0, rows)
            self.assertEqual(rows[0]["database_path"], first["database_path"])
            info = json.loads(Path(rows[0]["run_info_path"]).read_text())
            self.assertEqual(info["project_id"], first["project_id"])
            self.assertEqual(info["project_output_dir"], first["output_dir"])
        self.assertFalse((self.bin.parent / ".scopus-access").exists())
        self.assertFalse((self.bin.parent / "restricted_metadata").exists())

    def test_installed_multiline_query_keeps_original_text_and_wire_provenance(self):
        self.initialize()
        query = self.query()
        text = '\r\nSYNTHETIC_INSTALLED_QUERY\r\nAND\tTITLE("TWO  SPACES")\n'
        query.write_bytes(text.encode())
        code, rows = self.invoke(self.root, "check", "--query-file", str(query))
        self.assertEqual(code, 0, rows)
        info = json.loads(Path(rows[0]["run_info_path"]).read_text())
        task = json.loads(Path(info["manifest_path"]).read_text())
        operation = json.loads(Path(task["query_manifest_path"]).read_text())["queries"]["scopus_search"]
        self.assertEqual(operation["query"], text)
        self.assertEqual(operation["provenance"]["source_text"], text)
        self.assertEqual(operation["provenance"]["transformation"], "identity-utf8-v1")
        code, rows = self.invoke(self.root, "execute", "--run-info", rows[0]["run_info_path"], "--execute-live", local=False)
        self.assertEqual(code, 0, rows)
        code, rows = self.invoke(self.root, "usage")
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["requests_attempted"], 1)
        self.assertFalse((self.bin.parent / "restricted_metadata").exists())

    def test_installed_end_to_end_check_status_export_and_repeat_init_preserve_history(self):
        self.initialize()
        query = self.query()
        code, rows = self.invoke(self.root, "check", "--query-file", str(query), "--execute-live", local=False)
        self.assertEqual(code, 0, rows)
        run_info = rows[0]["run_info_path"]
        for command in ("status", "export"):
            code, rows = self.invoke(self.root, command, "--run-info", run_info)
            self.assertEqual(code, 0, rows)
        code, rows = self.invoke(self.root, "usage")
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["requests_attempted"], 1)
        code, rows = self.invoke(self.root, "init")
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["quota_state"], "NORMAL")
        code, rows = self.invoke(self.root, "usage")
        self.assertEqual(rows[0]["requests_attempted"], 1)
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SYNTHETIC_INSTALLED_CLI_CREDENTIAL", path.read_bytes())

    def test_installed_missing_and_corrupt_nearer_config_never_borrow_credentials(self):
        self.initialize()
        query = self.query()
        other = self.base / "uninitialized"
        other.mkdir()
        user = self.base / "mock-user"
        default = user / ".config/scopus-access/policy.json"
        default.parent.mkdir(parents=True)
        default.write_bytes((self.root / ".scopus-access/policy.json").read_bytes())
        env = {"SCOPUS_ACCESS_POLICY": str(self.root / ".scopus-access/policy.json"),
               "SCOPUS_TEST_USER_DIRECTORY": str(user)}
        for entry, arguments in (("scopus-access", ["search", "--query-file", str(query)]),
                                 ("scopus-fetch", [str(query)])):
            code, rows = self.invoke(other, *arguments, entry=entry, environment=env)
            self.assertEqual(code, 2, rows)
            self.assertEqual(rows[-1]["code"], "PROJECT_NOT_INITIALIZED")
            self.assertIn("init", rows[-1]["message"])
        child = self.root / "nested"
        control = child / ".scopus-access"
        control.mkdir(parents=True)
        for value in (None, b"{broken", b"{}"):
            policy = control / "policy.json"
            if value is not None:
                policy.write_bytes(value)
            code, rows = self.invoke(child, "search", "--query-file", str(query), environment=env)
            self.assertEqual(code, 2, rows)
        self.assertFalse(list((self.root / ".scopus-access/runs").iterdir()))

    def test_two_installed_processes_resume_unused_preflight_only_one_sends(self):
        initialized = self.initialize()
        query = self.query()
        query.write_bytes(b'\r\n(\n\tSYNTHETIC_INSTALLED_QUERY\r\n)\n')
        code, rows = self.invoke(self.root, "check", "--query-file", str(query), "--execute-live", local=False,
                                 environment={"SCOPUS_TEST_PROVIDER_ERROR": "1"})
        self.assertEqual(code, 6, rows)
        self.assertEqual(rows[-1]["requests_attempted"], 0)
        self.assertEqual(rows[-1]["stop_reason"], "secret_unavailable")
        info_path = rows[0]["run_info_path"]
        info = json.loads(Path(info_path).read_text())
        counter = self.base / "wire-counter"
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.defpath,
                   PYTHONDONTWRITEBYTECODE="1", SCOPUS_TEST_LOCAL_ONLY="0",
                   SCOPUS_TEST_PROVIDER_ERROR="0", SCOPUS_TEST_WIRE_COUNTER=str(counter),
                   PYTHONPATH=str(self.base / "missing-source"))
        processes = []
        try:
            for _ in range(2):
                processes.append(subprocess.Popen(
                    [str(self.python), "-I", str(self.harness), "scopus-access", "resume",
                     "--run-info", info_path, "--execute-live"], cwd=str(self.root), env=env,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            codes = []
            for process in processes:
                out, err = process.communicate(timeout=30)
                self.assertNotIn(b"SYNTHETIC_INSTALLED_CLI_CREDENTIAL", out + err)
                codes.append(process.returncode)
            self.assertEqual(sorted(codes), [0, 2])
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        self.assertEqual(counter.read_bytes(), b"sent\n")
        code, rows = self.invoke(self.root, "usage")
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["requests_attempted"], 1)
        with sqlite3.connect(initialized["database_path"]) as db:
            seeds = db.execute("SELECT reservation_id FROM task_reservation_ledger WHERE event_seq=1 AND admission_decision='ADMITTED'").fetchall()
            self.assertEqual(len(seeds), 1)
        code, rows = self.invoke(self.root, "status", "--run-info", info_path)
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["reservation_state"], "COMPLETED")
        code, rows = self.invoke(self.root, "export", "--run-info", info_path)
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["records_count"], 1)

    def test_two_installed_start_callers_reuse_prepared_terminal_failure_once(self):
        self.initialize()
        code,rows=self.invoke(self.root,"check","--query-file",str(self.query()))
        self.assertEqual(code,0,rows)
        code,rows=self.invoke(self.root,"execute","--run-info",rows[0]["run_info_path"],"--execute-live","--terminal",
                              environment={"SCOPUS_TEST_TERMINAL_RUN":"fail_open"})
        self.assertEqual(code,2,rows)
        source=rows[0]["run_info_path"]
        code,state=self.invoke(self.root,"status","--run-info",source)
        self.assertEqual((code,state[0]["phase"]),(0,"prepared_not_admitted"))
        counter=self.base/"start-counter"
        env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.defpath,PYTHONDONTWRITEBYTECODE="1",
                 SCOPUS_TEST_LOCAL_ONLY="0",SCOPUS_TEST_PROVIDER_ERROR="0",SCOPUS_TEST_WIRE_COUNTER=str(counter))
        processes=[]
        try:
            for _ in range(2):
                processes.append(subprocess.Popen([str(self.python),"-I",str(self.harness),"scopus-access","start",
                                                   "--run-info",source,"--execute-live"],cwd=str(self.root),env=env,
                                                   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE))
            codes=[]
            for process in processes:
                out,err=process.communicate(timeout=30)
                self.assertNotIn(b"SYNTHETIC_INSTALLED_CLI_CREDENTIAL",out+err)
                codes.append(process.returncode)
            self.assertEqual(sorted(codes),[0,2])
        finally:
            for process in processes:
                if process.poll() is None: process.kill();process.communicate()
        self.assertEqual(counter.read_bytes(),b"sent\n")
        code,rows=self.invoke(self.root,"inspect","--run-info",source)
        self.assertEqual((code,rows[0]["requests_attempted"]),(0,1))
        self.assertFalse(rows[0]["can_start"])

    def test_installed_same_names_repeat_and_rename_preserve_distinct_folder_identity(self):
        first = self.initialize()
        second = self.base / "second/survey"
        second.mkdir(parents=True)
        other = self.initialize(second)
        self.assertNotEqual(first["project_id"], other["project_id"])
        self.assertNotEqual(first["key_alias"], other["key_alias"])
        renamed = self.base / "renamed"
        self.root.rename(renamed)
        after = self.initialize(renamed)
        self.assertEqual(after["project_id"], first["project_id"])
        self.assertEqual(after["key_alias"], first["key_alias"])
        self.assertFalse(after["credential_written"])

    def test_two_installed_successor_grants_cannot_charge_same_predecessor_twice(self):
        self.initialize()
        query = self.query()
        # Missing telemetry still blocks. Numeric disagreements now reconcile
        # automatically and must not be used as a source of diagnostic grants.
        for expected in (5,5):
            code, rows = self.invoke(self.root,'check','--query-file',str(query),'--execute-live',local=False,
                environment={'SCOPUS_TEST_QUOTA_MISSING':'1'})
            self.assertEqual(code,expected,rows)
        source = rows[0]['run_info_path']
        drafts=[]
        for _ in range(2):
            code, rows = self.invoke(self.root,'diagnose','--run-info',source,'--correction','request_fix')
            self.assertEqual(code,0,rows)
            drafts.append(rows[0]['run_info_path'])
        counter=self.base/'successor-counter'
        env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.defpath,PYTHONDONTWRITEBYTECODE='1',
                 SCOPUS_TEST_LOCAL_ONLY='0',SCOPUS_TEST_WIRE_COUNTER=str(counter),SCOPUS_TEST_QUOTA_MISSING='1')
        processes=[]
        try:
            for draft in drafts:
                processes.append(subprocess.Popen([str(self.python),'-I',str(self.harness),'scopus-access',
                    'execute','--run-info',draft,'--execute-live'],cwd=str(self.root),env=env,
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE))
            # Drain both pipes concurrently: otherwise an event-producing
            # winner can fill stdout while the parent waits on the loser,
            # which is correctly waiting for the shared execution lock.
            with ThreadPoolExecutor(max_workers=2) as pool:
                outputs=list(pool.map(lambda process: process.communicate(timeout=30),processes))
            codes=[]
            for process,(out,err) in zip(processes,outputs):
                self.assertNotIn(b'SYNTHETIC_INSTALLED_CLI_CREDENTIAL',out+err)
                codes.append(process.returncode)
            self.assertEqual(sum(code==5 for code in codes),1,codes)
        finally:
            for process in processes:
                if process.poll() is None: process.kill();process.communicate()
        self.assertEqual(counter.read_bytes(),b'sent\n')
        database=self.root/'.scopus-access/control.sqlite'
        with sqlite3.connect(str(database)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM request_usage_log WHERE record_kind='ATTEMPT'").fetchone()[0],3)


    def test_installed_numeric_difference_automatically_continues_original_three_pages(self):
        self.initialize()
        query=self.query()
        code,rows=self.invoke(self.root,'check','--query-file',str(query),'--execute-live',local=False)
        self.assertEqual(code,0,rows)
        counter=self.base/'min-pages-counter'
        code,rows=self.invoke(self.root,'search','--query-file',str(query),'--max-requests','3','--page-size','1','--execute-live',
            local=False,environment={'SCOPUS_TEST_TOTAL':'3','SCOPUS_TEST_WIRE_COUNTER':str(counter)})
        self.assertEqual(code,0,rows)
        completed=next(r for r in rows if r.get('event')=='run_completed')
        self.assertEqual((completed['pages_completed'],completed['requests_attempted']),(3,3))
        self.assertFalse(any(r.get('event')=='paused' for r in rows))
        merged=[r for r in rows if r.get('event')=='quota_telemetry' and r['telemetry_reason']=='RATE_LIMIT_BALANCE_MIN_APPLIED']
        self.assertEqual([r['reconciled_remaining'] for r in merged],[98,97,96])
        self.assertEqual(counter.read_bytes(),b'sent\n'*3)

    def test_two_installed_resume_callers_repair_once_and_do_not_resend_saved_page(self):
        self.initialize()
        query=self.query()
        code,rows=self.invoke(self.root,'check','--query-file',str(query),'--execute-live',local=False)
        self.assertEqual(code,0,rows)
        code,rows=self.invoke(self.root,'search','--query-file',str(query),'--max-requests','3','--page-size','1','--execute-live',
            local=False,environment={'SCOPUS_TEST_TOTAL':'3','SCOPUS_TEST_LEGACY_BALANCE_PAUSE':'1'})
        self.assertEqual(code,5,rows)
        source=rows[0]['run_info_path']
        counter=self.base/'repair-resume-counter'
        env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.defpath,PYTHONDONTWRITEBYTECODE='1',
                 SCOPUS_TEST_LOCAL_ONLY='0',SCOPUS_TEST_TOTAL='3',SCOPUS_TEST_WIRE_COUNTER=str(counter))
        processes=[]
        try:
            for _ in range(2):
                processes.append(subprocess.Popen([str(self.python),'-I',str(self.harness),'scopus-access',
                    'resume','--run-info',source,'--execute-live'],cwd=str(self.root),env=env,
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE))
            with ThreadPoolExecutor(max_workers=2) as pool:
                outputs=list(pool.map(lambda process:process.communicate(timeout=30),processes))
            codes=[p.returncode for p in processes]
            self.assertEqual(sum(code==0 for code in codes),1,codes)
            for out,err in outputs:
                self.assertNotIn(b'SYNTHETIC_INSTALLED_CLI_CREDENTIAL',out+err)
        finally:
            for process in processes:
                if process.poll() is None: process.kill();process.communicate()
        self.assertEqual(counter.read_bytes(),b'sent\n'*2)
        with sqlite3.connect(str(self.root/'.scopus-access/control.sqlite')) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM quota_window_ledger WHERE record_kind='RETAINED_MIN_RECONCILIATION'").fetchone()[0],1)
            self.assertEqual(connection.execute("SELECT count(*) FROM request_usage_log WHERE record_kind='ATTEMPT'").fetchone()[0],4)
        code,rows=self.invoke(self.root,'inspect','--run-info',source)
        self.assertEqual(code,0,rows)
        self.assertEqual(rows[0]['pages_saved'],3)
        self.assertEqual(rows[0]['reserved_remaining'],0)


if __name__ == "__main__":
    unittest.main()
