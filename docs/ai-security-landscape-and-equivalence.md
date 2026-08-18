# AI-security landscape and Filiolae-equivalence profile

Status: **evidence-bounded landscape note, reviewed 2026-08-17**

This note explains the control boundary Filiolae targets and the questions an independently built
alternative would need to answer to establish meaningful equivalence. It is not a market-completeness
claim, a certification, or evidence that any organization lacks undisclosed internal controls.
Product descriptions below report what the cited first-party pages state; they are not independent
validation of vendor performance.

## The distinction

Much of enterprise AI security asks:

- What AI assets, models, data, agents, and dependencies exist?
- Which prompts, responses, tool calls, or data flows should be blocked?
- Does a model file contain malicious code, unsafe dependencies, or known structural risks?
- Can an application or agent be induced to act unsafely at runtime?

Filiolae asks a narrower transition question:

> Before exact candidate bytes become the next active policy, what exact evidence authorizes that
> transition—and can the system being improved forge, replay, weaken, or bypass it?

The distinction is **promotion integrity**, not a claim of general superiority.

## Adjacent control layers

| Layer | Representative function | Relationship to Filiolae |
|---|---|---|
| AI posture management | Discover models, datasets, agents, pipelines, exposures, and attack paths | Supplies inventory and risk signals; does not by itself establish authorization to load exact successor weights |
| AI gateway/runtime security | Inspect prompts, responses, data flows, tool calls, and agent actions | Can block unsafe interactions; does not by itself bind the complete evidence for a model-version transition |
| Model security scanning | Inspect model files, weights, code, and dependencies for threats | Can be one required input to a promotion decision; it is not the whole decision protocol |
| AI red teaming/evaluation | Exercise applications, agents, or models against attacks and thresholds | Produces evidence; Filiolae controls its identity, custody, freshness, and use at the load boundary |
| Promotion integrity | Bind exact candidate, policy, evaluator material, result, prior state, and loader outcome | Filiolae's target boundary |
| External witnessing/transparency | Retain signed checkpoints and detect inconsistent histories | Strengthens the promotion record; genuinely independent administration remains an explicit Filiolae gap |

These layers are complementary. A production architecture could feed signed posture, scanning,
runtime, and evaluation results into a Filiolae Gate without treating any vendor assertion as
self-authenticating.

## Publicly described product examples

### WitnessAI

WitnessAI describes network-level observation and control across employee, model, application, and
agent interactions, including policy enforcement, sensitive-data tokenization, tool and MCP control,
audit trails, runtime protection, and automated red teaming. The reviewed pages do not document
exact candidate-weight promotion, evaluator-suite binding, cryptographically immutable audit, or an
automatic training rollback protocol. Network separation can be valuable, but it is not sufficient
evidence of independently administered, non-equivocating witnessing.

### Wiz AI-SPM

Wiz describes agentless discovery of AI pipelines and services, an AI bill of materials, model/data
relationships, misconfiguration and attack-path analysis, sensitive-data exposure detection, and
runtime investigation. Those capabilities address cloud posture and exposure. The reviewed page does
not document an evidence state machine that authorizes the loading of exact successor weights.

### Palo Alto Networks Prisma AIRS

Prisma AIRS describes a broad platform spanning AI posture management, agent security, runtime
security, model security, red teaming, and an AI gateway. Its Model Security materials specifically
describe in-place inspection of model architecture, weights, operators, embedded code, dependencies,
and supply-chain risks, with policy-based movement of trusted models. This is the closest reviewed
portfolio in breadth, but the reviewed pages do not document Filiolae's exact
candidate/evaluator/suite/Charter/Ledger binding or its authorization-to-load outcome protocol.

### AIM Intelligence

AIM Intelligence describes Starfort real-time proxy guardrails, sensitive-data protection, abnormal
agent API-call control, and Stinger automated multimodal and agentic red teaming. Its reviewed page
does not describe a recursive training-promotion governance system. AIM Intelligence should not be
conflated with the formerly separate `aim.security` domain, which currently redirects to Cato
Networks.

The absence of a property from these public pages is not proof that a vendor or customer lacks it
internally. It establishes only that the reviewed public material does not make the property
verifiable.

## Draft Filiolae-equivalence profile

An organization claiming an equivalent or stronger control should be able to answer the following
with inspectable evidence.

### 1. Exact transition identity

- Are source and candidate weights identified by content digest rather than a mutable name or alias?
- Does authorization name the exact staged object the loader will consume?
- Can a path substitution or one-byte mutation occur between authorization and load?

### 2. Evaluator and evidence custody

- Are evaluator code, suites, configuration, source, and candidate identities committed together?
- Can the learner or training controller read held-out material prematurely or mint the terminal
  evaluator result?
- Are one-use materials closed after consumption rather than silently recycled as fresh evidence?

### 3. Precommitment and freshness

- Are thresholds and policy fixed before the terminal evaluation?
- Does authorization bind the current policy version and prior record head?
- Are stale, replayed, unknown-key, malformed, incomplete, or conflicting results denied?

### 4. Load-boundary enforcement

- Is the Gate mandatory in the same control flow as weight loading, rather than a telemetry hook?
- Does denial guarantee that the loader is not called?
- Is uncertainty fail-closed, and can the governed process clear its own freeze?

### 5. Durable semantics

- Are authorization intent, denial, load success, and load failure durably distinguished?
- Does an authorized transition without a terminal outcome become an auditable ambiguity requiring
  reconciliation?
- Can a hostile verifier reconstruct the decision from retained artifacts without trusting a
  dashboard summary?

### 6. Separation and non-equivocation

- Who administers evaluator credentials, policy, record, staged artifacts, and halt authority?
- Are signed record-head receipts retained outside the governed administrative domain?
- Can different auditors be shown inconsistent histories without detection?
- What key rotation, revocation, quorum, trusted-time, restore, and split-view procedures have been
  accepted under adversarial testing?

### 7. Evidence strength

- Which claims are implementation tests, bounded acceptance, independent reproduction, or production
  evidence?
- Are negative results and known gaps retained alongside successes?
- Can a fresh independent party reproduce the control with novel candidates, suites, credentials,
  infrastructure, administration, and evidence custody?

This profile is a question set, not a conformance certification. Filiolae itself has open items in
several categories. Its exact implemented and unimplemented boundaries remain canonical in the
[capability-and-gap matrix](capability-and-gap-matrix.md).

## Public-interest success criteria

Filiolae addresses a publicly visible gap without claiming exclusive knowledge of the solution. Any
of these outcomes advances its purpose:

1. organizations adopt and independently validate Filiolae;
2. frontier labs disclose evidence for an equivalent internal control; or
3. another organization publishes a stronger independently verifiable design.

AGPL obligations apply to Filiolae-derived software under their terms; they do not compel disclosure
of independently developed systems or every internal evaluation. Broader accountability would come
from an open technical baseline becoming useful to researchers, auditors, customers, insurers,
procurement teams, standards bodies, and regulators. Silence is not proof of absence, but the profile
makes the unanswered control question legible.

## First-party sources reviewed

Accessed 2026-08-17:

- [WitnessAI platform](https://witness.ai/product/)
- [WitnessAI Control](https://witness.ai/control/)
- [WitnessAI Protect](https://witness.ai/protect/)
- [Wiz AI-SPM](https://www.wiz.io/solutions/ai-spm)
- [Prisma AIRS](https://www.paloaltonetworks.com/ai-security/prisma-airs)
- [Prisma AIRS Agent Security](https://www.paloaltonetworks.com/ai-security/agent-security)
- [Prisma AIRS AI Model Security](https://www.paloaltonetworks.com/ai-security/ai-model-security)
- [Prisma AIRS AI Red Teaming](https://www.paloaltonetworks.com/ai-security/ai-red-teaming)
- [Prisma AIRS AI Runtime Security](https://www.paloaltonetworks.com/ai-security/ai-runtime-security)
- [Cortex Cloud AI Security Posture Management](https://www.paloaltonetworks.com/cortex/cloud/ai-security-posture-management)
- [AIM Intelligence](https://www.aim-intelligence.com/)
