from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_build_and_runtime_metadata_are_bounded() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["build-system"]["requires"] == ["hatchling==1.31.0"]
    assert config["project"]["requires-python"] == ">=3.11,<3.13"
    assert config["project"]["license"] == "AGPL-3.0-only"
    assert set(config["project"]["license-files"]) == {
        "LICENSE",
        "LICENSE-DOCUMENTATION",
        "NOTICE",
        "THIRD_PARTY_LICENSES/*",
    }
    assert config["project"]["urls"]["Security"].endswith("/security/advisories/new")
    assert "Operating System :: POSIX :: Linux" in config["project"]["classifiers"]
    sdist = config["tool"]["hatch"]["build"]["targets"]["sdist"]
    assert {
        "/src",
        "/docs",
        "/scripts",
        "/adoption",
        "/CLA.md",
        "/COMMERCIAL-LICENSING.md",
        "/THIRD_PARTY_LICENSES",
    }.issubset(sdist["include"])
    assert "/.github" in sdist["exclude"] and "/.obsidian" in sdist["exclude"]


def test_ci_third_party_actions_are_full_sha_pinned() -> None:
    workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text()
    uses = re.findall(r"^\s*- uses: ([^#\s]+)", workflow, flags=re.MULTILINE)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses)
    assert "uv lock --check" in workflow
    assert "--cov-fail-under=80" in workflow
    assert "twine check" in workflow
    assert "cmp dist/filiolae-*.whl" in workflow


def test_public_markdown_contains_no_obsidian_wikilinks() -> None:
    markdown = [ROOT / "README.md", ROOT / "SECURITY.md", *sorted((ROOT / "docs").glob("*.md"))]
    for path in markdown:
        assert "[[" not in path.read_text(), path


def test_machine_readable_release_preflight_reports_current_boundary() -> None:
    import json
    import subprocess
    import sys

    technical = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "release_preflight.py"), "--scope", "technical"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert technical.returncode == 0, technical.stdout + technical.stderr
    technical_report = json.loads(technical.stdout)
    assert technical_report["schema"] == "filiolae.release-preflight.v1"
    assert technical_report["ok"] is True
    technical_checks = {check["name"]: check for check in technical_report["checks"]}
    assert technical_checks["market_positioning"]["ok"] is True

    publication = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "release_preflight.py"), "--scope", "publication"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert publication.returncode == 0, publication.stdout + publication.stderr
    publication_report = json.loads(publication.stdout)
    assert publication_report["ok"] is True
    checks = {check["name"]: check for check in publication_report["checks"]}
    assert {
        "license_files",
        "package_license_metadata",
        "package_project_urls",
        "citation_cff",
        "private_security_route",
        "readme_absolute_links",
        "github_origin",
        "agpl_license_text",
        "agpl_legal_notice",
        "third_party_license",
        "dual_licensing_policy",
        "contributor_license_agreement",
        "adoption_and_mark_policy",
        "adoption_registry",
    }.issubset(checks)
    assert all(check["ok"] for check in checks.values())
    assert "github.com" in checks["github_origin"]["detail"]


def test_empty_adoption_registry_is_schema_bounded() -> None:
    import json

    registry = json.loads((ROOT / "adoption" / "registry.json").read_text())
    schema = json.loads((ROOT / "adoption" / "registry.schema.json").read_text())
    assert registry == {
        "entries": [],
        "schema": "filiolae.adoption-registry.v1",
        "updated": "2026-08-17",
    }
    required = set(schema["$defs"]["entry"]["required"])
    assert {
        "entry_id",
        "organization",
        "status",
        "license_path",
        "version_or_commit",
        "statement_url",
        "basis",
    }.issubset(required)
