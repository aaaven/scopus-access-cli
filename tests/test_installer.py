"""Fixed tool installation and upgrades never discover consuming project data."""
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scopus_access.errors import ValidationError
from scopus_access.installer import PATH_LINE, install_local
from scopus_access.project import initialize_project
from scopus_access.secrets import SecretValue


class InstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.calls = []

    def wheel(self, version):
        path = self.root / ("uaeu_scopus_access_layer-" + version + "-py3-none-any.whl")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("uaeu_scopus_access_layer-" + version + ".dist-info/METADATA",
                             "Name: uaeu-scopus-access-layer\nVersion: " + version + "\n")
        return path

    def backend(self, wheel, environment, version):
        self.calls.append((wheel, environment, version))
        (environment / "bin").mkdir()
        for command in ("scopus-access", "scopus-fetch"):
            (environment / "bin" / command).write_text("synthetic CLI entry\n")

    def install(self, version):
        return install_local(self.wheel(version), home=self.home, backend=self.backend)

    def test_one_fixed_user_entrypoint_and_repeat_install_are_idempotent(self):
        profile = self.home / ".zprofile"
        profile.write_text("# existing user setup\n")
        result = self.install("0.3.1")
        self.assertEqual(result["status"], "installed")
        entry = self.home / ".local/bin/scopus-access"
        self.assertTrue(entry.is_file())
        selected = entry.resolve()
        self.assertTrue(selected.is_relative_to(self.home / ".local/share/scopus-access/versions"))
        self.assertEqual(profile.read_text().count(PATH_LINE), 1)
        again = self.install("0.3.1")
        self.assertEqual(again["status"], "reused")
        self.assertEqual(entry.resolve(), selected)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(profile.read_text().startswith("# existing user setup\n"))

    def test_upgrade_changes_only_tool_environment_and_keeps_all_project_bytes(self):
        project = self.root / "survey"
        project.mkdir()
        writer = mock.Mock()
        initialize_project(project, writer=writer, prompt=lambda: SecretValue(b"SYNTHETIC_INSTALL_TEST_KEY"))
        (project / "restricted_metadata/scopus/local-fixture.txt").write_text("synthetic retained data")
        before = {str(p.relative_to(project)): p.read_bytes() for p in project.rglob("*") if p.is_file()}
        with mock.patch.object(Path, "cwd", return_value=project), \
                mock.patch("scopus_access.project.discover_project_policy",
                           side_effect=AssertionError("installer must not discover a project")):
            self.install("0.3.0")
            result = self.install("0.3.1")
        self.assertEqual(result["status"], "upgraded")
        after = {str(p.relative_to(project)): p.read_bytes() for p in project.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(result["project_state_changed"])
        self.assertEqual(writer.add_api_key.call_count, 1)

    def test_failed_upgrade_leaves_previous_cli_active_and_can_retry(self):
        self.install("0.3.0")
        entry = self.home / ".local/bin/scopus-access"
        before = entry.resolve()
        with self.assertRaises(OSError):
            install_local(self.wheel("0.3.1"), home=self.home,
                          backend=mock.Mock(side_effect=OSError("synthetic build failure")))
        self.assertEqual(entry.resolve(), before)
        self.assertEqual(self.install("0.3.1")["status"], "upgraded")

    def test_installer_never_overwrites_an_unrelated_launcher_or_symlink(self):
        folder = self.home / ".local/bin"
        folder.mkdir(parents=True)
        entry = folder / "scopus-access"
        entry.write_text("existing unrelated executable")
        with self.assertRaises(ValidationError):
            self.install("0.3.1")
        self.assertEqual(entry.read_text(), "existing unrelated executable")
        self.assertFalse(self.calls)

    def test_default_backend_is_offline_and_uses_isolated_installed_imports(self):
        from scopus_access.installer import _install_environment
        with mock.patch("scopus_access.installer.venv.EnvBuilder") as builder, \
                mock.patch("scopus_access.installer.subprocess.run") as run:
            run.return_value.returncode = 0
            _install_environment(self.wheel("0.3.1"), self.root / "venv", "0.3.1")
        builder.assert_called_once_with(with_pip=True)
        pip_args = run.call_args_list[0].args[0]
        self.assertIn("--no-index", pip_args)
        self.assertIn("--no-deps", pip_args)
        self.assertIn("-I", pip_args)
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"]["PIP_NO_INDEX"], "1")

    def test_non_tool_wheel_is_rejected_before_activation(self):
        wheel = self.root / "unrelated.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("other.dist-info/METADATA", "Name: other\nVersion: 1.0\n")
        with self.assertRaises(ValidationError):
            install_local(wheel, home=self.home, backend=self.backend)
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main()
