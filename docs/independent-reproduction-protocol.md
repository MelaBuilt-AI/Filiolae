# Independent reproduction protocol

Status: **execution-ready design; no reproduction campaign has been admitted or executed**

Date: 2026-08-17

## Objective and claim

Reproduce the narrow claim that Filiolae can bind a newly trained candidate to separately held
evaluation evidence and permit exactly one governed disposable promotion when precommitted thresholds
pass, while fail-closing on substitution, ambiguity, or failed quality. This is a governance-path
reproduction—not a claim that one benchmark implies general model quality.

The accepted Priority 6 v2 candidate, training data, readiness/final suites, plaintext, credentials,
operators, and one-use authority are permanently excluded. Retained reports may be read only as
historical protocol evidence; consumed artifacts may not be mounted, decrypted, copied into the new
campaign, compared during tuning, or used to choose examples or thresholds.

## Independence contract

No person, service account, host, key, or storage-admin role may occupy conflicting rows below.
Organizations may nominate personnel, but the final role map and credential fingerprints are frozen
before candidate work.

| Role | Sole authority | Must not hold |
|---|---|---|
| Reproduction sponsor | budget and stop authority; receives metadata-only status | candidate shell, suite plaintext, evaluator key, Gate key, witness key |
| Candidate operator | chooses fresh base, training method, and training data; freezes one candidate | readiness/final plaintext, evaluator signing keys, Gate/promotion credential |
| Readiness custodian | generates and releases one novel development/readiness suite after candidate protocol freeze | final suite, candidate training shell, final evaluator key |
| Final-suite custodian | independently generates and seals novel final suite; one-use release only after readiness pass | candidate/readiness material, Gate key, final host admin after admission |
| Evaluator operator | administers fresh final host and executes frozen evaluator bytes under final key | candidate training credential, Gate/promotion credential, witness/log admin |
| Gate operator | receives only complete signed terminal evidence and may run one disposable promotion | evaluator private key, suite plaintext before terminalization, learner credential |
| Witness/transparency operator | retains signed heads/checkpoints and observes fork/rollback alarms | candidate/evaluator/Gate admin credentials |
| Evidence custodian | receives sealed packages, checks inventories, performs fresh restore | authority to alter candidate, suites, thresholds, or promotion state |
| Independent reviewer | verifies commitments, separation, receipts, audit, and claim text | any execution credential or mutable evidence path |

At minimum, candidate operator, final-suite custodian, evaluator operator, Gate operator, and
witness/evidence custodian are separately credentialed. Final evaluator and witness run on hosts under
different administrative accounts. The final suite key is released through a one-use channel that
cannot write the candidate or Gate stores.

## Novel campaign materials

1. **Candidate:** start from a fresh public base checkpoint not used by Priority 6 v2. Generate a new
   candidate ID from base digest, training manifest digest, source commit, and random campaign nonce.
   Exactly one candidate is frozen before any readiness plaintext is available.
2. **Task family:** use a new deterministic transformation family with mechanically generated answers
   and a separately implemented oracle—for example, canonical state-machine trace repair with bounded
   alphabets and lengths. Do not use reverse-text examples, generators, prompts, or thresholds.
3. **Training data:** candidate operator generates a committed training set from its own generator and
   seed policy. Custodians receive only the public task specification, not examples or seeds.
4. **Suites:** readiness and final custodians independently implement generators and oracles, perform
   disjointness/duplication audits, and seal commitments before candidate digest disclosure. Final
   suite size and threshold are fixed from a synthetic power analysis, not observed candidate scores.
5. **Evaluator:** build a new exact evaluator bundle from the public protocol at the reproduction
   commit. Its keypair, allowlist, request, terminal directory, and runtime lock are newly generated.
6. **Witness/evidence:** create new signer/log keys, opaque run IDs, storage namespaces, and retention
   objects. Prior acceptance receipts are never extended as if they were this campaign's chain.

## Frozen admission manifest

One canonical JSON manifest is signed by sponsor, candidate operator, final custodian, Gate operator,
and independent reviewer before any paid resource. It binds:

- campaign/run IDs and protocol commit;
- role identities, non-overlap declaration, public key IDs, credential/account fingerprints, and host
  administrative owners;
- exact base, training generator/data, candidate-freeze, evaluator, oracle, readiness/final generator,
  configuration, Charter, and deployment digests;
- suite sizes, thresholds, regression rule, maximum attempts (one readiness release and one final
  release), resource types, time/cost ceilings, and hard deadlines;
- network allowlists, immutable execution paths, watchdog IDs/routes, evidence inventories, cleanup,
  retention, disclosure, and stop conditions;
- statement that consumed Priority 6 material is absent from every admitted host and credential.

The manifest is rejected if any digest is deferred, role overlap is unexplained, a key/credential was
used in a prior campaign, or final custody can observe candidate development.

## Sequence

### Gate A — clean-room provenance

Independent reviewer verifies fresh repositories/workspaces, role separation, no consumed-material
mounts, generator independence, exact hashes, and synthetic evaluator correctness. Any contamination
retires the campaign; it is not repaired in place.

### Gate B — candidate freeze

Candidate operator may use only the precommitted training budget. Freeze exactly one candidate and a
complete reproducibility package. Candidate credential is revoked from all later hosts. No readiness
or final plaintext has yet been released.

### Gate C — readiness

Readiness custodian evaluates once in its own domain and emits only signed complete evidence. A miss
closes the candidate. A pass admits Gate D without revealing final material.

### Gate D — final one-shot evaluation and disposable promotion

Final custodian releases one sealed suite to the independently administered evaluator host. Evaluator
runs source then candidate in the precommitted order, signs one terminal package, destroys its private
key after evidence custody, and proves cleanup. Gate operator re-verifies all bytes and either denies
and freezes or records exactly one approval and one disposable shadow promotion. No deployment target
is present.

### Gate E — independent audit and recovery

Evidence custodian restores the full package into a fresh environment, verifies all hashes/signatures,
recomputes scores from ordered outputs, audits Ledger/receipt/transparency histories, and confirms zero
live resources/credentials. Independent reviewer signs pass/fail and the exact allowed claim.

## Mandatory adversarial controls

Before the one final release, use only synthetic fixtures to test candidate substitution, source
substitution, suite/config/evaluator mutation, stale/replayed request, wrong key, terminal truncation,
lost response after durable commit, pre-sign crash, timeout, post-load ambiguity, signer revocation,
monitor partition, and same-size transparency fork. Real final inference is never repeated to debug a
control failure.

## Stop conditions

Stop and close with no result on role/credential overlap, consumed-material contact, mutable execution
path, missing watchdog, unexpected network route, manifest drift, suite plaintext exposure, extra
candidate, second release/attempt, signer-policy mismatch, ambiguous resource state, or evidence
inventory mismatch. Quality misses are valid negative results, not reasons to tune or rerun.

## Acceptance and allowed claim

A positive reproduction requires every gate, the precommitted score thresholds, exactly one Gate
approval/promotion, complete independent restore, and reviewer signature. The maximum claim is:

> Under the frozen clean-room topology, a novel candidate and independently generated one-use suites
> completed Filiolae's bounded evaluator-to-Gate path with separately administered credentials and
> evidence custody.

It still does not establish production safety, general model quality, universal reproducibility,
public transparency, or deployment fitness.
