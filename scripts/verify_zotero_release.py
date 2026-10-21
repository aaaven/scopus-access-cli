#!/usr/bin/env python3
"""Audit local release archives without network, credentials or runtime data."""

import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def verify(path, repository):
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            members = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
        package = "scopus_access/"
        for name in members:
            if not (name.startswith(package) and name.endswith(".py")
                    or ".dist-info/" in name and name.split(".dist-info/", 1)[1]
                    in {"METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD", "LICENSE"}):
                raise ValueError("Unexpected wheel member")
    else:
        with tarfile.open(path, "r:gz") as archive:
            members = {}
            for member in archive.getmembers():
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError("Non-regular source archive member")
                parts = PurePosixPath(member.name).parts
                if len(parts) < 2:
                    raise ValueError("Invalid source archive member")
                name = "/".join(parts[1:])
                members[name] = archive.extractfile(member).read()
        package = "src/scopus_access/"
        allowed_files = {
            'pyproject.toml',
            'setup.cfg',
            'README.md',
            'CHANGELOG.md',
            'CONTRIBUTING.md',
            'AGENTS.md',
            '.gitignore',
            'PKG-INFO',
            'MANIFEST.in',
            'docs/ARCHITECTURE.md',
            'docs/CLIENT-COMPARISON.md',
            'docs/DEVELOPMENT.md',
            'docs/DOI-ENRICHMENT.md',
            'docs/DOI-PRIORITY.md',
            'docs/FEEDBACK-F01-F05.md',
            'docs/ITERATION-0.4.1.md',
            'docs/PUBLISHER-HTML-INTEGRATION.md',
            'docs/PUBLISHER-HTML-LIVE-PLAN.md',
            'docs/PUBLISHER-HTML-PROBE.md',
            'docs/PUBLISHER-HTML.md',
            'docs/QUOTA-RECONCILIATION.md',
            'docs/RELEASE-0.6.0.md',
            'docs/RELEASE-0.6.1.md',
            'docs/RELEASE-0.7.0.md',
            'docs/RELEASE-0.8.0.md',
            'docs/USAGE.md',
            'docs/VALIDATION.md',
            'docs/ZOTERO.md',
            'examples/README.md',
            'examples/doi-priority-v1.0.json',
            'examples/offline-policy.json',
            'examples/synthetic-preflight-task.json',
            'examples/synthetic-query-manifest.json',
            'examples/synthetic-release-evidence.json',
        }
        allowed_files.update("scripts/" + source.name for source in (repository / "scripts").glob("*.py"))
        egg_files = {"PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "top_level.txt", "requires.txt"}
        for name in members:
            if not (name in allowed_files or name.startswith(package) and name.endswith(".py")
                    or name.startswith("tests/") and name.endswith(".py")
                    or name.startswith("src/uaeu_scopus_access_layer.egg-info/") and name.rsplit("/", 1)[1] in egg_files):
                raise ValueError("Unexpected source archive member")
    for name in members:
        parts = PurePosixPath(name).parts
        if ".." in parts or PurePosixPath(name).is_absolute():
            raise ValueError("Unsafe archive member")
    expected = {package + source.name: source.read_bytes()
                for source in (repository / "src/scopus_access").glob("*.py")}
    actual = {name: value for name, value in members.items() if name.startswith(package)}
    if actual != expected:
        raise ValueError("Release package differs from current source")
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "package_modules": len(expected), "archive_files": len(members), "status": "verified"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", type=Path, nargs="+")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    for source in args.archives:
        print(json.dumps(verify(source, root), sort_keys=True))
