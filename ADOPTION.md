# Public adoption registry

Filiolae maintains a public, reviewable registry of self-reported evaluation and adoption. Its
machine-readable source is [`adoption/registry.json`](adoption/registry.json), validated against the
repository's bounded schema and publication preflight.

## Who must or may register

- **Commercial licensees:** registration is mandatory no later than the commercial license's effective
  date. The executed agreement supplies the legal obligation; this document does not itself grant a
  commercial license.
- **AGPL users:** registration is voluntary. Organizations evaluating, researching, piloting, deploying,
  or discontinuing Filiolae or a fork are explicitly invited to report that status.
- **Reviewers and contributors:** source review, issue participation, and a contribution do not imply
  adoption and should not be registered unless the participant chooses to report actual use.

## Minimal public record

Each entry contains a stable identifier, legal or chosen public organization name, status, license
path, exact version/commit, first-use month, nonsensitive scope, public statement URL, update date, and
whether it is self-reported or contract-required. Do not submit personal addresses, credentials,
nonpublic infrastructure details, vulnerabilities, or confidential contract terms.

Statuses have narrow meanings:

- `evaluation`: bounded assessment; no adoption conclusion implied;
- `research`: an ongoing research activity uses Filiolae or an identified derivative;
- `pilot`: a bounded real-workflow trial;
- `deployment`: an organization reports operational use;
- `discontinued`: previously reported use has ended.

## How to add or update an entry

Open an **Adoption disclosure** issue or pull request containing the registry entry and a statement URL
controlled or expressly approved by the named organization. MelaBuilt AI checks schema and provenance
but does not independently certify claims in voluntary statements. Corrections append history through
Git; they do not erase a commercial license's historical listing.

The registry deliberately contains no telemetry. Absence from it does **not** prove that an organization
has never inspected, evaluated, used, forked, or independently reimplemented Filiolae. A registry entry
does not confer certification, endorsement, production approval, or additional software rights.
