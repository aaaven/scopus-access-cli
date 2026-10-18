"""Publication checks reject local state without exposing its contents."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


script = Path(__file__).resolve().parent.parent / "scripts/verify_repository.py"
spec = importlib.util.spec_from_file_location("scopus_release_layout", script)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseLayoutTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def create(self, path, text="synthetic"):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return Path(path)

    def test_runtime_and_secret_files_rejected_even_if_present_in_index(self):
        paths = [self.create(name) for name in (
            ".scopus-access/policy.json", "restricted_metadata/private.json",
            "runtime/control.sqlite-wal", "records.jsonl", "private.key", "local-policy.json",
        )]
        result = release.scan_repository(self.root, paths)
        self.assertEqual(result["violations_count"], len(paths))
        self.assertTrue(all(p["code"] == "RUNTIME_OR_SECRET_FILE" for p in result["violations"]))

    def test_personal_paths_private_key_material_and_local_links_rejected(self):
        personal = "/" + "Users/test-user/private/"
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        paths = [self.create("docs/LOCAL.md", personal + "\n[local](/private/tmp/private.txt)"),
                 self.create("private.txt", marker)]
        result = release.scan_repository(self.root, paths)
        self.assertEqual({p["code"] for p in result["violations"]},
                         {"PERSONAL_ABSOLUTE_PATH", "LOCAL_MACHINE_LINK", "PRIVATE_KEY_MATERIAL"})

    def test_public_relative_links_and_synthetic_fixtures_accepted(self):
        paths = [self.create("README.md", "[guide](docs/USAGE.md)"),
                 self.create("docs/USAGE.md", "[home](../README.md)"),
                 self.create("examples/synthetic-query-manifest.json", '{"synthetic": true}')]
        result = release.scan_repository(self.root, paths)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(result["secret_reads"], 0)

    def test_symlink_and_broken_relative_document_link_rejected(self):
        target = self.create("source.txt")
        (self.root / "link.txt").symlink_to(self.root / target)
        paths = [Path("link.txt"), self.create("README.md", "[missing](missing.md)")]
        result = release.scan_repository(self.root, paths)
        self.assertEqual({p["code"] for p in result["violations"]},
                         {"SYMLINK", "BROKEN_DOCUMENT_LINK"})
