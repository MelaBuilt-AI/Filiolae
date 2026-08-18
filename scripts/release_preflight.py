#!/usr/bin/env python3
"""Machine-readable checks for Filiolae's technical/publication release surface."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

FULL_SHA_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
WIKILINK = re.compile(r"\[\[")
SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}
PRIVATE_PATH_MARKERS = (
    "/home/" + "mela_ai",
    "/mnt/c/" + "Users/",
    "Owner/Documents/" + "Mela AI",
    "192.168." + "0.20",
)
PLACEHOLDER_SECURITY_TEXT = "A private reporting channel will be published"
SECURITY_ROUTE = "https://github.com/MelaBuilt-AI/Filiolae/security/advisories/new"
AGPL_LICENSE_SHA256 = "d8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee"
PRIME_RL_LICENSE_SHA256 = "f5118b9c9e98b0f4076214ee13f68d5f73c13b077c44544cb9a0c4ed9155065c"


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode() for item in result.stdout.split(b"\0") if item]


def _text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _markdown_files(root: Path, tracked: list[Path]) -> list[Path]:
    return [path for path in tracked if path.suffix.lower() == ".md"]


def _check_links(root: Path, markdown: list[Path]) -> Check:
    broken: list[str] = []
    for path in markdown:
        content = _text(path) or ""
        for raw in MARKDOWN_LINK.findall(content):
            target = raw.strip().split(maxsplit=1)[0].strip("<>").split("#", 1)[0]
            if not target or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target):
                continue
            if not (path.parent / target).resolve().exists():
                broken.append(f"{path.relative_to(root)} -> {raw}")
    return Check(
        "markdown_links",
        not broken,
        "all checkout-relative Markdown links resolve" if not broken else "; ".join(broken),
    )


def _check_public_text(root: Path, tracked: list[Path], markdown: list[Path]) -> list[Check]:
    wikilinks = [str(path.relative_to(root)) for path in markdown if WIKILINK.search(_text(path) or "")]
    private_run_links = [
        str(path.relative_to(root))
        for path in markdown
        if "github.com/MelaBuilt-AI/Filiolae/actions/runs/" in (_text(path) or "")
    ]
    private_markers: list[str] = []
    secrets: list[str] = []
    for path in tracked:
        content = _text(path)
        if content is None:
            continue
        relative = str(path.relative_to(root))
        for marker in PRIVATE_PATH_MARKERS:
            if marker in content:
                private_markers.append(f"{relative}:{marker}")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                secrets.append(f"{relative}:{label}")
    return [
        Check("no_obsidian_wikilinks", not wikilinks, "none" if not wikilinks else ", ".join(wikilinks)),
        Check(
            "no_private_actions_links",
            not private_run_links,
            "none" if not private_run_links else ", ".join(private_run_links),
        ),
        Check(
            "no_private_machine_paths",
            not private_markers,
            "none" if not private_markers else ", ".join(private_markers),
        ),
        Check("no_obvious_secrets", not secrets, "none" if not secrets else ", ".join(secrets)),
    ]


def _check_archives(root: Path, tracked: list[Path]) -> Check:
    archives = [path for path in tracked if path.name.endswith((".tar.gz", ".tgz"))]
    issues: list[str] = []
    secret_bytes = {label: re.compile(pattern.pattern.encode()) for label, pattern in SECRET_PATTERNS.items()}
    private_bytes = tuple(marker.encode() for marker in PRIVATE_PATH_MARKERS)
    for path in archives:
        relative = str(path.relative_to(root))
        try:
            with tarfile.open(path, "r:gz") as archive:
                for member in archive.getmembers():
                    parts = Path(member.name).parts
                    if member.name.startswith("/") or ".." in parts:
                        issues.append(f"{relative}:{member.name}:unsafe_path")
                    if not (member.isfile() or member.isdir()):
                        issues.append(f"{relative}:{member.name}:unsafe_type")
                    if not member.isfile():
                        continue
                    handle = archive.extractfile(member)
                    data = b"" if handle is None else handle.read()
                    if any(marker in data for marker in private_bytes):
                        issues.append(f"{relative}:{member.name}:private_path")
                    for label, pattern in secret_bytes.items():
                        if pattern.search(data):
                            issues.append(f"{relative}:{member.name}:{label}")
        except (OSError, tarfile.TarError) as exc:
            issues.append(f"{relative}:unreadable:{exc}")
    return Check(
        "archive_safety",
        not issues,
        f"{len(archives)} archive(s) safe" if not issues else "; ".join(issues),
    )


def _check_workflow(root: Path) -> Check:
    path = root / ".github" / "workflows" / "quality.yml"
    content = _text(path)
    if content is None:
        return Check("sha_pinned_actions", False, "quality workflow is missing")
    uses = re.findall(r"^\s*- uses: ([^#\s]+)", content, flags=re.MULTILINE)
    bad = [item for item in uses if FULL_SHA_ACTION.fullmatch(item) is None]
    return Check(
        "sha_pinned_actions",
        bool(uses) and not bad,
        f"{len(uses)} action(s) pinned" if uses and not bad else f"unusable/unpinned: {bad}",
    )


def _check_claim_reconciliation(root: Path) -> Check:
    required_documents = (
        "docs/capability-and-gap-matrix.md",
        "docs/ai-security-landscape-and-equivalence.md",
        "docs/independent-reproduction-protocol.md",
        "docs/operational-hardening-plan.md",
        "docs/public-preview-readiness-plan.md",
        "docs/public-preview-release-notes.md",
        "docs/publication-surface-audit.md",
    )
    missing = [name for name in required_documents if not (root / name).is_file()]
    current_surface = {
        "README.md": _text(root / "README.md") or "",
        "SECURITY.md": _text(root / "SECURITY.md") or "",
        "RELEASE_CHECKLIST.md": _text(root / "RELEASE_CHECKLIST.md") or "",
        "CHANGELOG.md": _text(root / "CHANGELOG.md") or "",
    }
    stale_phrases = (
        "Priority 6 v2 has no trained candidate or inference result",
        (
            "Priority 6 v2's complete-evidence path now has bounded distinct-UID fixture acceptance, "
            "but no trained"
        ),
        "prepared private-CI rehearsal,\n  but it is not accepted",
        "real paired-model evaluation and evaluator isolation remain unvalidated",
    )
    stale = [
        f"{name}:{phrase[:48]}"
        for name, content in current_surface.items()
        for phrase in stale_phrases
        if phrase in content
    ]
    matrix = _text(root / required_documents[0]) or ""
    required_matrix_terms = (
        "Consumed and closed",
        "Priority 6 v2 real-model path",
        "Receipt-transparency interoperability",
        "Multi-party promotion",
        "Public source preview",
    )
    absent_terms = [term for term in required_matrix_terms if term not in matrix]
    ok = not missing and not stale and not absent_terms
    detail_parts = []
    if missing:
        detail_parts.append(f"missing={missing}")
    if stale:
        detail_parts.append(f"stale={stale}")
    if absent_terms:
        detail_parts.append(f"matrix_terms_missing={absent_terms}")
    return Check(
        "claim_reconciliation",
        ok,
        "current surfaces bind the canonical claim register" if ok else "; ".join(detail_parts),
    )


def _check_market_positioning(root: Path) -> Check:
    readme = _text(root / "README.md") or ""
    landscape = _text(root / "docs/ai-security-landscape-and-equivalence.md") or ""
    required = {
        "README.md": ("publicly visible gap", "not a claim that frontier labs lack"),
        "docs/ai-security-landscape-and-equivalence.md": (
            "not proof",
            "not a conformance certification",
            "do not compel disclosure",
            "independently developed systems",
        ),
    }
    content = {"README.md": readme, "docs/ai-security-landscape-and-equivalence.md": landscape}
    missing = [
        f"{name}:{term}"
        for name, terms in required.items()
        for term in terms
        if term.casefold() not in content[name].casefold()
    ]
    forbidden_terms = (
        "first and only",
        "only platform",
        "no frontier lab has",
        "all frontier labs lack",
        "proves that frontier labs",
    )
    overclaims = [
        f"{name}:{term}"
        for name, text in content.items()
        for term in forbidden_terms
        if term.casefold() in text.casefold()
    ]
    ok = not missing and not overclaims
    detail = "market boundary and public-evidence caveat present"
    if not ok:
        detail = f"missing={missing}; overclaims={overclaims}"
    return Check("market_positioning", ok, detail)


def _metadata(root: Path) -> dict[str, Any]:
    return tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def technical_checks(root: Path) -> list[Check]:
    tracked = _tracked_files(root)
    markdown = _markdown_files(root, tracked)
    metadata = _metadata(root)
    checks = [
        _check_links(root, markdown),
        *_check_public_text(root, tracked, markdown),
        _check_archives(root, tracked),
        _check_workflow(root),
        _check_claim_reconciliation(root),
        _check_market_positioning(root),
    ]
    checks.extend(
        [
            Check(
                "supported_python_range",
                metadata.get("requires-python") == ">=3.11,<3.13",
                str(metadata.get("requires-python")),
            ),
            Check(
                "pre_alpha_classifier",
                "Development Status :: 2 - Pre-Alpha" in metadata.get("classifiers", []),
                "pre-alpha classifier present",
            ),
            Check(
                "release_documents",
                all(
                    (root / name).is_file()
                    for name in ("CHANGELOG.md", "CONTRIBUTING.md", "RELEASE_CHECKLIST.md", "SECURITY.md")
                ),
                "required release documents present",
            ),
        ]
    )
    return checks


def _check_adoption_registry(root: Path) -> Check:
    path = root / "adoption" / "registry.json"
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return Check("adoption_registry", False, f"unreadable: {exc}")
    entries = registry.get("entries")
    if registry.get("schema") != "filiolae.adoption-registry.v1" or not isinstance(entries, list):
        return Check("adoption_registry", False, "wrong schema or entries")
    required = {
        "entry_id",
        "organization",
        "status",
        "license_path",
        "version_or_commit",
        "first_use_month",
        "scope",
        "statement_url",
        "last_updated",
        "basis",
    }
    statuses = {"evaluation", "research", "pilot", "deployment", "discontinued"}
    identifiers: set[str] = set()
    issues: list[str] = []
    for index, entry in enumerate(entries):
        label = f"entry[{index}]"
        if not isinstance(entry, dict) or not required.issubset(entry):
            issues.append(f"{label}:missing_fields")
            continue
        identifier = entry["entry_id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", identifier):
            issues.append(f"{label}:entry_id")
        elif identifier in identifiers:
            issues.append(f"{label}:duplicate_id")
        identifiers.add(identifier)
        if entry["status"] not in statuses:
            issues.append(f"{label}:status")
        if entry["license_path"] not in {"AGPL-3.0-only", "commercial"}:
            issues.append(f"{label}:license_path")
        if entry["basis"] not in {"voluntary", "contract-required"}:
            issues.append(f"{label}:basis")
        if (entry["license_path"] == "commercial") != (entry["basis"] == "contract-required"):
            issues.append(f"{label}:commercial_basis")
        if not isinstance(entry["statement_url"], str) or not entry["statement_url"].startswith("https://"):
            issues.append(f"{label}:statement_url")
        if not isinstance(entry["first_use_month"], str) or not re.fullmatch(
            r"[0-9]{4}-(?:0[1-9]|1[0-2])", entry["first_use_month"]
        ):
            issues.append(f"{label}:first_use_month")
        if not isinstance(entry["last_updated"], str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}", entry["last_updated"]
        ):
            issues.append(f"{label}:last_updated")
    detail = f"{len(entries)} valid public entries" if not issues else "; ".join(issues)
    return Check("adoption_registry", not issues, detail)


def _check_licensing_policy(root: Path) -> list[Check]:
    license_text = _text(root / "LICENSE") or ""
    licenses = _text(root / "LICENSES.md") or ""
    commercial = _text(root / "COMMERCIAL-LICENSING.md") or ""
    adoption = _text(root / "ADOPTION.md") or ""
    cla = _text(root / "CLA.md") or ""
    trademarks = _text(root / "TRADEMARKS.md") or ""
    certification = _text(root / "CERTIFICATION.md") or ""
    contributing = _text(root / "CONTRIBUTING.md") or ""
    prime_rl_license = _text(root / "THIRD_PARTY_LICENSES" / "prime-rl-Apache-2.0.txt") or ""
    cli = _text(root / "src" / "filiolae" / "cli.py") or ""
    return [
        Check(
            "agpl_license_text",
            hashlib.sha256(license_text.encode()).hexdigest() == AGPL_LICENSE_SHA256,
            "canonical SPDX AGPL-3.0-only text present" if license_text else "missing",
        ),
        Check(
            "agpl_legal_notice",
            all(
                marker in cli
                for marker in (
                    "AGPL-3.0-only",
                    "ABSOLUTELY NO WARRANTY",
                    SECURITY_ROUTE.rsplit("/security", 1)[0],
                )
            ),
            "CLI help carries copyright/license/warranty/source notice",
        ),
        Check(
            "third_party_license",
            hashlib.sha256(prime_rl_license.encode()).hexdigest() == PRIME_RL_LICENSE_SHA256,
            "pinned prime-rl Apache-2.0 text present" if prime_rl_license else "missing",
        ),
        Check(
            "dual_licensing_policy",
            all(
                marker in commercial
                for marker in (
                    "It is not a commercial license",
                    "Every Filiolae commercial license",
                    "confidential exception for a licensee",
                    "AGPL route remains available",
                )
            )
            and "AGPL-3.0-only" in licenses,
            "AGPL plus separate commercial policy with mandatory public listing",
        ),
        Check(
            "contributor_license_agreement",
            all(
                marker in cla
                for marker in (
                    "You retain ownership",
                    "AGPL-3.0-only",
                    "separate commercial or enterprise license",
                    "I accept the Filiolae Contributor License Agreement v1.0",
                )
            )
            and "CLA.md" in contributing,
            "non-assignment CLA and recorded acceptance present",
        ),
        Check(
            "adoption_and_mark_policy",
            "registration is voluntary" in adoption
            and "Commercial licensees" in adoption
            and "no Filiolae certification program is active" in certification
            and "do not grant rights" in trademarks,
            "voluntary AGPL registry and trademark/certification boundaries present",
        ),
        _check_adoption_registry(root),
    ]


def publication_checks(root: Path) -> list[Check]:
    metadata = _metadata(root)
    license_files = sorted(
        {path.name for path in root.glob("LICENSE*")} | ({"NOTICE"} if (root / "NOTICE").is_file() else set())
    )
    urls = metadata.get("urls") if isinstance(metadata.get("urls"), dict) else {}
    security = (root / "SECURITY.md").read_text(encoding="utf-8")
    remote = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    remote_url = remote.stdout.strip() if remote.returncode == 0 else ""
    required_licenses = {"LICENSE", "LICENSE-DOCUMENTATION", "NOTICE"}
    cff = _text(root / "CITATION.cff") or ""
    readme = _text(root / "README.md") or ""
    relative_readme_links = [
        raw
        for raw in MARKDOWN_LINK.findall(readme)
        if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", raw.strip().split(maxsplit=1)[0].strip("<>"))
    ]
    return [
        Check(
            "license_files",
            required_licenses.issubset(license_files),
            ", ".join(license_files) or "missing",
        ),
        Check(
            "package_license_metadata",
            metadata.get("license") == "AGPL-3.0-only",
            str(metadata.get("license") or "missing"),
        ),
        Check(
            "package_project_urls",
            bool(urls.get("Source") and urls.get("Issues") and urls.get("Security")),
            json.dumps(urls, sort_keys=True) if urls else "missing",
        ),
        Check(
            "citation_cff",
            all(
                marker in cff
                for marker in (
                    "cff-version: 1.2.0",
                    "version: 0.1.0",
                    "license: AGPL-3.0-only",
                    'repository-code: "https://github.com/MelaBuilt-AI/Filiolae"',
                )
            ),
            "complete pre-alpha citation metadata" if cff else "missing",
        ),
        Check(
            "private_security_route",
            PLACEHOLDER_SECURITY_TEXT not in security and SECURITY_ROUTE in security,
            "configured" if SECURITY_ROUTE in security else "exact route missing",
        ),
        Check(
            "readme_absolute_links",
            not relative_readme_links,
            "all README links are package-index-safe"
            if not relative_readme_links
            else str(relative_readme_links),
        ),
        Check(
            "github_origin",
            bool(
                re.fullmatch(r"(?:https://github\.com/|git@github\.com:)[^/\s]+/[^\s]+(?:\.git)?", remote_url)
            ),
            remote_url or "origin missing",
        ),
        *_check_licensing_policy(root),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1])
    parser.add_argument("--scope", choices=("technical", "publication"), default="technical")
    args = parser.parse_args()
    root = args.root.resolve()
    checks = technical_checks(root)
    if args.scope == "publication":
        checks.extend(publication_checks(root))
    ok = all(check.ok for check in checks)
    print(
        json.dumps(
            {
                "schema": "filiolae.release-preflight.v1",
                "scope": args.scope,
                "ok": ok,
                "checks": [asdict(check) for check in checks],
            },
            indent=2,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
