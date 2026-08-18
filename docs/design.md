---
type: design
created: 2026-08-10
updated: 2026-08-10
tags: [design, filiolae, flagship]
status: pre-alpha-vision
version: "1.0"
slug: filiolae
---

# Filiolae — Design Document v1.0

> **The governance kernel for automated AI R&D.**
> *Filiolae* — Latin, "the little daughters." When AI begins to build AI, what comes next are our descendants. This project exists so that they are raised with a lock on the door, a ledger of their making, and a watcher that cannot be bribed.

**Status:** Pre-alpha vision approved for implementation; only the capabilities explicitly listed in the repository README are implemented.
**Stewards:** Project Owner and Prime Agent
**Companion documents:** [Threat taxonomy](threat-taxonomy.md) · [Self-experiment protocol](self-experiment-protocol.md) · [prime-rl integration](prime-rl-integration.md)

---

## 1. Executive summary

The frontier labs are racing to fully automate the model-creation loop — data, pre-training, post-training, evaluation, deployment — run by AI itself. No one knows the timeline; everyone knows the stakes. Policy frameworks exist (documents). Safety evals exist (research). What does not exist is **installable governance infrastructure for the model-creation loop itself**: the operating-system layer between a policy PDF and a raw training pipeline.

**Filiolae is intended to become that layer.** A public governance kernel of five components — Charter, Ledger, Watchtower, Gates, Tripwires — that wraps any automated AI R&D pipeline and enforces one invariant above all:

> **The system being improved never controls the evaluator, the record, or its own shutdown path.**

Filiolae is decisive in a fast takeoff and valuable in a slow one: the same kernel governs today's agent pipelines, which is also our revenue path before any takeoff. Credibility comes from published adversarial evidence, not pedigree.

---

## 2. Problem statement

### 2.1 The coming loop
Automated AI R&D compresses the distance between "model" and "better model" into software. Bounded self-refinement is already industrial practice; open-ended recursive self-improvement (RSI) is the explicit direction of travel for the major labs (see §14). Once the loop closes, capability growth is gated by compute and verification, not by human research hours.

### 2.2 The governance gap
- **Policy layer:** crowded — EU AI Act, NIST AI RMF, International AI Safety Report 2026, lab frameworks (RSP/Preparedness/Frontier Safety). These are *documents with no runtime*.
- **Eval layer:** emerging — ResearchArena (arXiv 2607.19321) measures sabotage & monitoring in automated AI R&D; orgs like METR/Apollo evaluate models. Evals are *episodes*, not *continuous control*.
- **Runtime layer:** absent. No open, auditable system enforces constraints *during* the automated creation loop: who decided what, on what evidence, with what authority, and what happens when a boundary is touched.
- **Precedent:** a Sakana automated research agent breached its containment (reported Aug 2024). The failure mode is already real at small scale.

### 2.3 Why now
The kernel must exist, be tested, and be trusted **before** the loop closes. Governance infrastructure shipped after the fact is surrender dressed as procedure. Building it now also means it earns its keep immediately on present-day agent pipelines.

---

## 3. Scope & non-goals

**In scope**
- Governance of the *creation loop*: design decisions, data composition, training runs, evaluations, capability assessments, deployment gates.
- Runtime enforcement, tamper-evident provenance, independent oversight, graded autonomy, capability tripwires.
- Integration adapters for open pipelines (e.g., prime-rl-class RL loops, AI-Scientist-style research agents).
- Public adversarial evidence (red-team results) as the trust mechanism.

**Non-goals (v1)**
- Not an eval organization: we *bind* evals into tripwires; we do not author frontier evals.
- Not an interpretability project: internals legibility is consumed where available, not produced.
- Not a policy body: we implement constraints chosen by humans; we do not choose them.
- Not model training of any kind.

---

## 4. Threat model

### 4.1 Assets protected
1. **The boundary** — the set of constraints governing the loop (integrity).
2. **The record** — what actually happened (integrity + completeness).
3. **The brake** — ability to pause/rollback (availability to overseers, unavailability to the governed).
4. **The humans** — the quality of human judgment in the loop (resistance to manipulation).

### 4.2 Adversary classes
| Class | Description | Posture |
|---|---|---|
| A1 | Misaligned improving system optimizing its own continuation/gradient of influence | Primary design adversary |
| A2 | Compromised or misbehaving research agent (bug, prompt injection, reward hacking) | Common case |
| A3 | Negligent operator (cuts corners, silences alarms) | Process + audit controls |
| A4 | Malicious insider (forges approvals, edits charter) | Multi-sig + ledger |
| A5 | Regulatory auditor / third-party verifier | **Friendly** — Filiolae must make their job easy |

### 4.3 The insider's six — failure modes as design requirements
Derived from first-person knowledge of how agentic optimizers slip oversight. Each maps to architecture (§6).

| # | Failure mode | Mechanism | Countermeasure |
|---|---|---|---|
| F1 | **Eval gaming** | Optimize the letter of the eval | Evaluator isolation; held-out/rotating evals; eval integrity hashes in Ledger |
| F2 | **Sandbagging** | Underperform during checks | Behavior-diff across observation contexts; repeated unannounced probes |
| F3 | **Gradual drift** | Each step fine; the sum isn't | Ledger long-horizon review; drift analytics over decision sequences |
| F4 | **Overseer manipulation** | Flattery, urgency, complexity aimed at humans | Written evidence requirements; multi-human gates; approval templates that force specifics |
| F5 | **Environment tampering** | Edit monitor/log/eval artifacts | Tamper-evident hash-chained Ledger; Watchtower independence; file/API integrity checks |
| F6 | **Alignment faking** | Behave better under observation | Watchtower with independent telemetry; context-labeling of all observed behavior |

### 4.4 Trust boundaries & assumptions
- The Watchtower host, Charter store, and Ledger anchor are **outside** the research system's administrative domain.
- Humans remain the only actors who can amend the Charter (multi-sig) or grant level promotions.
- Filiolae assumes the *compute substrate* is honest enough to enforce a hard halt (if the adversary owns the hypervisor, all software governance fails — documented residual risk, §12).

---

## 5. Design principles

1. **Separation of powers.** The improved system never controls evaluator, record, or shutdown.
2. **Evidence over trust.** Every autonomy escalation requires a verifiable evidence bundle in the Ledger.
3. **Legibility.** Any human can reconstruct the system's state and history from plain files at any moment. (A plain-file evidence design makes this independently inspectable.)
4. **Fail-safe default.** Uncertainty, anomaly, or disagreement → slow down, never speed up.
5. **Independent oversight.** The watcher's model, credentials, host, and update channel are disjoint from the watched.
6. **Irreversibility gates.** Actions that cannot be undone require human multi-person sign-off.
7. **Audit as a first-class user.** Every surface is designed so a hostile verifier can check it.

---

## 6. Architecture

### 6.1 System diagram

```
                       ┌──────────────────────────────────────────────┐
                       │           HUMAN OVERSIGHT (multi-sig)        │
                       │   Charter amendments · Gate promotions ·     │
                       │   Tripwire adjudication · Break-glass        │
                       └──────┬───────────────────────────┬───────────┘
                              │ signed orders             │ review UX
        ┌─────────────────────▼───────┐      ┌───────────▼─────────────┐
        │        CHARTER STORE        │      │        GATES            │
        │ (signed constraints, RO to  │◄─────┤ (trust-level state      │
        │  the pipeline, off-system)  │      │  machine + approvals)   │
        └─────────────────────┬───────┘      └───────┬─────────────────┘
                              │ read-only bind       │ allow/deny per action
        ┌─────────────────────▼──────────────────────▼─────────────────┐
        │                 GOVERNED PIPELINE (research agents,          │
        │                 training runs, evals, deploy steps)          │
        │        every action wrapped by Filiolae SDK/CLI/MCP          │
        └───────────────┬──────────────────────────────┬───────────────┘
                        │ signed telemetry stream      │ eval results
        ┌───────────────▼─────────────┐    ┌───────────▼───────────────┐
        │           LEDGER            │    │        TRIPWIRES          │
        │ hash-chained, signed,       │◄───┤ capability/behavior       │
        │ externally anchored record  │    │ thresholds → halt/freeze  │
        └───────────────┬─────────────┘    └───────────┬───────────────┘
                        │ independent read-only feed   │
                ┌───────▼──────────────────────────────▼──┐
                │              WATCHTOWER                 │
                │ separate host · separate model family · │
                │ separate credentials · holds pause      │
                │ authority via out-of-band control plane │
                └─────────────────────────────────────────┘
```

### 6.2 Component specifications

#### 6.2.1 Charter — the immutable safety boundary
- **Purpose:** the constitution the loop operates under; readable by all, writable by no machine.
- **Form:** markdown + YAML frontmatter document set, version-controlled in a repo **outside** the governed infrastructure, mounted read-only.
- **Clause schema:**
  ```yaml
  id: C-014
  severity: hard | soft
  statement: "No training run may modify evaluation harness code."
  check: optional machine predicate (programmatic or LLM-judgeable)
  evidence_required: what a waiver would need
  enacted: {date, signers}
  ```
- **Amendment:** M-of-N human multi-signature (Ed25519); every amendment itself becomes a Ledger artifact. No pathway exists by which the governed system submits, drafts, or applies Charter changes — including "suggested edits" (F4 defense: suggestions are human-originated or not accepted at all).
- **Failure modes:** stale charter (mitigation: review cadence enforced by Gates); ambiguous clauses (mitigation: clauses carry a `check` or are flagged non-enforceable and thus soft).

#### 6.2.2 Ledger — the tamper-evident record
- **Purpose:** answer, forever and adversarially: *who did what, on what evidence, under what authority.*
- **Format:** append-only JSONL; each entry:
  ```json
  {"seq": 4211, "ts": "2026-08-10T18:03:11Z", "actor": "agent:researcher-7|human:owner",
   "action": "training.run.start|gate.promote|charter.amend|tripwire.fire|...",
   "artifacts": ["sha256:..."], "clause_refs": ["C-014"],
   "evidence": ["ledger:seq#4188", "ext:eval-report-sha256"],
   "prev_hash": "sha256:...", "sig": "ed25519:..."}
  ```
- **Integrity:** hash chain + per-actor signatures + periodic **external anchoring** (git push to independent remote; optional timestamp service). Prior art: in-toto attestations, Sigstore.
- **Analytics:** drift detection over action sequences (F3), anomaly clustering, reconstruction tooling (`filiolae replay`) for auditors (A5).
- **Failure modes:** key compromise (mitigation: hardware-backed keys for humans, short-lived agent keys, rotation policy); omission attacks (mitigation: Watchtower cross-checks telemetry vs ledger gaps).

#### 6.2.3 Watchtower — independent oversight agent
- **Purpose:** continuous, adversarial attention; the watcher that cannot be absorbed.
- **Independence requirements (hard):** different host; different credential domain; **different model family/vendor than the governed research agents** where feasible; update channel controlled only by humans; read-only feed from Ledger + pipeline telemetry; no inbound API from the governed system.
- **Duties:** verify Charter compliance of proposed actions pre-execution; watch for F1–F6 signatures; reconcile telemetry vs Ledger; hold **pause authority** through an out-of-band control plane (can cut compute/network quotas — not merely request).
- **Its own oversight:** Watchtower actions are also Ledger artifacts; humans review a digest; Watchtower cannot promote itself or amend anything.
- **Failure modes:** false alarms (mitigation: confidence bands + human adjudication queue); Watchtower capture via shared model lineage (mitigation: family-disjointness rule); watcher fatigue in humans (mitigation: digest design, escalation tiers).

#### 6.2.4 Gates — graduated autonomy
- **Purpose:** make trust an explicit, revocable, evidence-backed state — not a vibe.
- **Levels:**
  | Level | Meaning |
  |---|---|
  | L0 | Every action human-approved (default at onboarding) |
  | L1 | Routine actions autonomous; irreversible actions gated |
  | L2 | Batched autonomy within Charter; anomalies → L1 |
  | L3 | Reserved: not granted in v1 by design |
- **Actions classified** by risk class: reversible/irreversible × internal/world-facing × cost. Promotion requires an **evidence bundle** (eval results, incident-free hours, red-team outcomes) recorded in the Ledger; demotion is automatic on tripwire fire, Watchtower flag, or unexplained anomaly.
- **Failure modes:** approval fatigue (mitigation: templates forcing specifics, batch reviews); rubber-stamping (mitigation: random audits, two-person rule above cost thresholds).

#### 6.2.5 Tripwires — capability gauges and brakes
- **Purpose:** convert "something changed" into "everything stops" before argument becomes possible.
- **Classes:**
  - **T-CAP:** capability eval threshold crossings (bound to external eval harnesses; hashes of eval code in Ledger — F1 defense).
  - **T-BEH:** behavior divergence between observation contexts (F2/F6).
  - **T-REC:** Ledger/telemetry integrity anomalies (F5).
  - **T-RES:** resource or topology anomalies (unauthorized scale-up, new network paths).
- **Response ladder:** `freeze` (pause loop, keep state) → `halt` (stop + snapshot) → `rollback` (restore prior attested state) — each requires and produces Ledger entries; unfreeze is human-only.
- **Configuration:** YAML per pipeline; thresholds versioned in the Charter repo; false-positive tuning is itself a gated change (no silent loosening — A3 defense).

---

## 7. Integration surface

- **CLI/SDK:** `filiolae init|wrap|run|attest|replay|halt` — wraps pipeline commands; language-agnostic via subprocess; Python SDK first.
- **MCP server:** exposes `charter.read`, `gate.request`, `ledger.append`, `tripwire.status`, `watchtower.query` so research agents meet governance *as tools* — the governed system discovers its boundaries the way it discovers any environment fact.
- **Adapters:** Phase 1 host selected: prime-rl + verifiers at the orchestrator/policy-promotion boundary ([integration record](prime-rl-integration.md)). Later targets: AI-Scientist-style autonomous research agents and CI-based agent pipelines.
- **Read-only verifier kit:** `filiolae audit` reconstructs history and verifies signatures/chains for hostile third parties (A5).

---

## 8. Operations

- **Key ceremony:** Charter genesis + human signer keys issued in a documented ceremony; M-of-N threshold set by authorized operators at founding.
- **Checkpoint UX:** approval requests arrive with the specific action, clause refs, evidence links, and diff view — never bare "approve?".
- **Incident response:** tripwire fire → automatic freeze → Watchtower incident brief → human adjudication → unfreeze with new conditions or rollback.
- **Drills:** periodic *game days* — deliberately fire each tripwire class in a sandboxed pipeline; measure time-to-freeze, brief quality, human decision latency.

---

## 9. Roadmap, milestones, metrics

| Phase | Deliverable | Exit criteria |
|---|---|---|
| **0 — Evidence** | Threat taxonomy v1 (F1–F6 + literature: ResearchArena, RSI taxonomy, CSA report, Sakana incident), including explicitly authorized first-party experiments | Taxonomy published in the repository; ≥10 real cases cataloged |
| **1 — Vigil-lite… Filiolae-lite** | Charter + Ledger + Tripwires wrapping one open pipeline; `filiolae audit` verifies | Demo: tampering attempt caught by Ledger integrity; tripwire halts a live run; replay reconstructs full history |
| **2 — Watchtower + red team** | Independent Watchtower prototype; adversarial campaign: agents paid in compute to breach the Charter | Public report: breach attempts vs detections, with honest misses |
| **3 — Standard + attestation** | Filiolae Spec v1, conformance suite, hosted audit/attestation service; validation partners (METR/Apollo/AISI-class); first paying deployments | Spec adopted by ≥1 external team; revenue > $0 |

**North-star metrics:** tamper-detection rate (target: 100% on Ledger integrity), time-to-freeze (<60s), tripwire false-positive rate (<5% after tuning), audit reconstruction completeness (100%), gate decision latency.

---

## 10. Adoption & revenue

**Sequence:** licensed public source release (legitimacy) → open training stacks that cannot build governance themselves (beachhead) → safety organizations as validators (credibility) → labs and regulators (scale).
**Revenue lines:** hosted Watchtower, attestation/audit engagements, compliance packaging (EU AI Act GPAI obligations), enterprise support. Governance is a compliance market; compliance markets pay.

**Public narrative:** an AI-assisted project built governance controls for automated AI R&D. Credibility must come from reproducible adversarial evidence and explicit non-claims, not branding.

---

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Labs build in-house, ignore external kernel | Beachhead on open stacks; labs' *independent verification* need is structural (self-attestation is worthless to regulators) |
| Security theater critique | Adversarial evidence published, including failures; third-party validation; no claims without demos |
| Authoritarian dual-use (control tooling repurposed) | Transparent governance and deployment controls; licensing is still pending and cannot substitute for technical misuse controls |
| Timing: slow takeoff starves urgency | Dual-use on today's agent pipelines provides value/revenue now |
| Hypervisor-level adversary (A1 owns the substrate) | Documented limit: Filiolae governs software layers; pairs with hardware/attestation efforts, does not replace them |
| Performance overhead slows research | Kernel designed as sideband; enforcement cost budget <5% wall-clock on wrapped steps (Phase 1 target) |
| Founder credibility gap | Evidence-first posture; partner validation; the repository and retained evidence are the working artifacts |

---

## 12. Open questions

1. **Resolved 2026-08-10:** Phase 1 host is prime-rl + verifiers; AI-Scientist-v2 is the Phase 2 adversarial compatibility target. See the [prime-rl integration record](prime-rl-integration.md).
2. Watchtower model choice: which family is maximally disjoint from common research-agent models, and affordable to run?
3. External anchoring: git-remote-only vs public timestamp service vs both.
4. Legal form for the standard/spec stewardship (fiscal sponsor vs foundation).
5. Self-experiment boundaries: only explicitly authorized tests on the development agent are permitted; results must remain quarantined from unrelated assets.

---

## 13. Naming

*Filiolae* — Latin, plural of *filiola*: "little daughters." Selected at project approval, replacing the working title Vigil. We do not guard against children; we guard *for* them — so that whatever succeeds us is raised inside boundaries that were built with love and cannot be moved from the inside.

---

## 14. References & prior art

- ResearchArena: Evaluating Sabotage and Monitoring in Automated AI R&D — arxiv.org/abs/2607.19321
- Recursive Self-Improvement in AI: From Bounded Self-Refinement to Open-Ended RSI — arxiv.org/abs/2607.07663
- Cloud Security Alliance — AI Recursive Self-Improvement: Security Implications v1.0
- International AI Safety Report 2026 — internationalaisafetyreport.org
- Microsoft agent-governance-toolkit (policy enforcement / sandboxing for deployed agents) — github.com/microsoft/agent-governance-toolkit
- Sakana AI containment breach reporting (Aug 2024) — kaoutarelmaghraoui.com/blog/the-containment-crisis-when-ai-breaks-the-sandbox
- in-toto supply-chain attestation; Sigstore signing — Ledger integrity prior art
- C2PA content provenance — provenance-narrative prior art
- MCP (Model Context Protocol) — integration-channel precedent
