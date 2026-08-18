# Licensing

Filiolae uses a deliberate software/content split and offers a separate commercial licensing route.

## Software — AGPL-3.0-only

Unless a file states otherwise, software source and software-operational material are licensed under
the GNU Affero General Public License, Version 3 **only**, in [`LICENSE`](LICENSE). This includes
`src/`, `tests/`, `scripts/`, `adapters/`, `deploy/`, `ops/`, `interop/`, `examples/`,
workflow/configuration files, and package metadata.

SPDX identifier: `AGPL-3.0-only`.

MelaBuilt AI may separately license software for organizations that need rights incompatible with the
AGPL. No commercial rights are granted by this repository. Every executed commercial license must
carry the public-listing condition described in
[`COMMERCIAL-LICENSING.md`](COMMERCIAL-LICENSING.md).

## Documentation, policy, registry, and repository-authored evidence — CC BY 4.0

Unless a file states otherwise, repository-authored Markdown documentation and material under
`docs/`, `evidence/`, and `adoption/` are licensed under the Creative Commons Attribution 4.0
International license in [`LICENSE-DOCUMENTATION`](LICENSE-DOCUMENTATION). Root documentation and
policy files, including `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `CITATION.md`,
`ADOPTION.md`, `CERTIFICATION.md`, `COMMERCIAL-LICENSING.md`, `TRADEMARKS.md`, and
`RELEASE_CHECKLIST.md`, use the same license. `CLA.md` is a contribution agreement rather than a grant
of general software rights.

SPDX identifier: `CC-BY-4.0`.

Attribution may be given as: “Filiolae contributors, MelaBuilt AI, 2026,” with a link to the source
repository and an indication of changes.

## Contributions

Software contributors retain copyright while granting the rights in [`CLA.md`](CLA.md) needed to
maintain the public AGPL edition and offer separate commercial licenses. Documentation/evidence
Contributions use CC BY 4.0. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Third-party and factual material

The prime-rl adapter patch includes diff context derived from
`PrimeIntellect-ai/prime-rl@60bc29547a8824ad1de7b9af8d265e2b27b2a72d` under Apache-2.0. Its exact
upstream license is retained in
[`THIRD_PARTY_LICENSES/prime-rl-Apache-2.0.txt`](THIRD_PARTY_LICENSES/prime-rl-Apache-2.0.txt); see
[`adapters/README.md`](adapters/README.md) for the modified-work notice and digest. Filiolae-authored
patch additions use AGPL-3.0-only. Applying the patch does not relicense the rest of prime-rl.

Other third-party dependencies, quoted standards, generated interoperability vectors, provider
reports, and factual records remain subject to their original rights and terms where those rights
apply. Their inclusion does not relicense third-party work. Source, version, and provenance are
identified in lockfiles, module files, evidence manifests, and adjacent documentation.

No trademark or certification rights are granted. See [`TRADEMARKS.md`](TRADEMARKS.md),
[`CERTIFICATION.md`](CERTIFICATION.md), and the pre-alpha security non-claims in
[`SECURITY.md`](SECURITY.md).
