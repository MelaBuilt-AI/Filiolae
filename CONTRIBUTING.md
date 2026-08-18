# Contributing

Filiolae is a security-sensitive pre-alpha project. Focused issue reports, documentation corrections,
reproduction results, and narrowly scoped pull requests are welcome after the public source preview.
A proposal does not become governance evidence until its exact bytes and tests pass the relevant gate.

## License of contributions

Filiolae keeps a public `AGPL-3.0-only` software edition and may offer the same software under separate
commercial terms. Software contributors retain copyright and must accept the narrow
[`Filiolae Contributor License Agreement v1.0`](CLA.md), which grants the Project Steward only the
rights needed to publish, adapt, sublicense, and dual-license the Contribution. It is not a copyright
assignment.

Include this exact statement in the pull request description or an associated recorded comment:

> I accept the Filiolae Contributor License Agreement v1.0 for this contribution.

An entity acceptance must identify the entity and come from an authorized representative. Pull
requests with software Contributions cannot be merged without recorded acceptance. Issue reports and
review comments that contain no Contribution require no CLA.

Contributions to documentation or repository-authored evidence are provided under CC BY 4.0. By
submitting, you represent that you have the right to do so. See [`LICENSES.md`](LICENSES.md). Do not
submit third-party material whose license or provenance is unclear.

## Adoption and commercial licensing

Any organization may use the public software under AGPL-3.0-only if it complies with that license.
Organizations needing different rights may request a separate commercial agreement; every commercial
licensee must be listed in the public adoption registry. AGPL users are invited—but not required by
project policy merely for using the AGPL route—to disclose evaluation or adoption voluntarily. See
[`COMMERCIAL-LICENSING.md`](COMMERCIAL-LICENSING.md), [`ADOPTION.md`](ADOPTION.md), and the
[`licensing FAQ`](docs/licensing-faq.md).

## Development

```bash
uv sync --locked --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest --cov=filiolae --cov-fail-under=80
uv build
uv run twine check dist/*
uv run python scripts/release_preflight.py --scope technical
```

Use a fresh path for game days; never overwrite retained evidence. Governance/security changes require
fail-closed negative tests in addition to a happy path. Tests must prove no authority is granted after
malformed, missing, stale, timed-out, revoked, or ambiguous evidence. Claims in README, SECURITY,
design, and runbooks must agree with the
[`capability-and-gap matrix`](docs/capability-and-gap-matrix.md) and must not upgrade bounded evidence
into production or independent evidence.

## Security reports

Do not place sensitive exploit details in a public issue, discussion, or pull request. Use GitHub
Private Vulnerability Reporting at
<https://github.com/MelaBuilt-AI/Filiolae/security/advisories/new>. Include the affected commit,
threat-boundary assumptions, minimal reproducer, impact, and a proposed coordination window.
