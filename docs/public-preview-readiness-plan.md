# Public-preview readiness plan

Status: **accepted v0.1.0 preparation record; repository visibility and post-open verification are tracked as separate release actions**

Date: 2026-08-17

## Objective

Bring Filiolae to an evidence-bound public-source-preview decision gate without converting bounded
research results into production claims. The preview must be reproducible from public bytes, clear
about consumed evidence, legally reviewable, and safe to inspect without any live service or paid
resource.

## Work packages

1. **Truth maintenance**
   - reconcile README, SECURITY, release, changelog, and roadmap statements with retained evidence;
   - publish one capability-and-gap matrix with evidence class, exact support, limits, and next gate;
   - add a mechanical claim-drift check for the highest-risk stale statements.
2. **Independent reproduction design**
   - define a clean-room protocol with new candidate, new sealed suites, different operators,
     credentials, hosts, evaluator/witness custody, and evidence custody;
   - forbid use of the accepted Priority 6 v2 candidate or consumed readiness/final material;
   - define admission, stop, acceptance, and disclosure gates before any execution.
3. **Operational hardening design**
   - consequence-rank recovery, reboot persistence, key rotation/revocation, multi-party promotion,
     monitoring/rollback, provider-independent recovery, and split-view transparency exercises;
   - distinguish release-blocking controls from post-preview research gates.
4. **Publication preparation**
   - settle repository licensing/metadata, citation, contribution, vulnerability reporting, and
     release notes while the repository stays private;
   - make the machine-readable publication preflight pass;
   - validate source, wheel/sdist, fresh install, and private hosted CI at one exact commit.
5. **Decision gate**
   - freeze the reviewed commit and artifact hashes;
   - report exact readiness, residual non-claims, and proposed public-preview action before changing
     repository visibility, publishing a package, creating a public release, or announcing it.

## Acceptance criteria

- Every top-level status statement agrees with the capability-and-gap matrix.
- Retained results cite repository evidence or an exact private workflow record and preserve their
  stated scope.
- Consumed Priority 6 material remains closed and is not accessed or reused.
- Independent reproduction can be administered without sharing candidate, suite, evaluator,
  witness, or custody authority with the original campaign.
- Operational-hardening priorities have consequence, entry criteria, procedure, evidence, stop
  conditions, and claim unlocked.
- Technical and publication preflights, tests, lint/format, locked dependency check, deterministic
  builds, metadata checks, and fresh-wheel smoke pass.
- Repository visibility changes only through a separately approved release action; readiness work alone grants no visibility authority.

## Non-claims at this gate

Public-preview readiness does not establish production security, independent reproduction,
independent transparency observation, trusted time, general model quality, unattended operation,
or deployment fitness. It does not reopen any consumed candidate or evaluation suite.
