# Design Import Adjudication

Status: current source-repository import ledger.

Owner: `proofkit`.

## Problem

The pre-cutover local repository contains many design documents and
implementation plans. Importing them wholesale would duplicate current
authority, preserve stale release and private-source facts, and route future
agents through historical PR reasoning instead of the current code, specs,
package records, and backlog.

Not importing them without an explicit ledger would create the opposite risk:
durable invariants could be silently lost during the public cutover.

## Decision

Scope: this ledger covers pre-cutover `docs/*-design.md` and
`docs/*-implementation-plan.md` files that are absent from the current public
source tree. Pre-cutover same-path non-design docs such as
`proofkit-contract-map.md` and `release-process.md` are outside this ledger
because their current public versions exist at the same paths and own their
rewritten public-source content.

The public repository imports only source-repository design documents that own a
current durable boundary not already represented by current specs, shipped
contract records, package-public docs, code, tests, or this backlog.

Merged implementation plans are not imported as current authority. Their useful
invariants must move into code, tests, specs, package-public docs, or explicit
backlog rows. Retained source-repository design documents are not package
authority unless `package.json`, package verification, and release evidence
explicitly admit them.

The remaining pre-cutover design documents are adjudicated below. They are not
deleted from history; they are excluded from the public source tree because
their current durable content is already owned elsewhere or because their
remaining value is historical implementation context.

This ledger classifies import decisions. It is not package authority, not a
replacement for the current owner surfaces named below, and not a proof that
every old sentence remains true.

## Current Imported Design Surfaces

These source-repository design documents are admitted because they define
current lifecycle and requirement-source boundaries used to adjudicate later
documents:

- `document-lifecycle-boundary-design.md`
- `requirement-source-admission-design.md`
- `spec-overview-claim-boundary-design.md`
- `requirement-source-transition-design.md`

## Excluded Implementation Plans

Implementation plans are historical after merge. These pre-cutover plans are
not imported as current authority:

- `admission-diagnostic-hardening-implementation-plan.md`
- `adoption-contract-envelope-admission-implementation-plan.md`
- `agent-decision-router-implementation-plan.md`
- `browser-renderer-consolidation-implementation-plan.md`
- `compact-proof-contract-projections-implementation-plan.md`
- `coverage-view-input-compose-implementation-plan.md`
- `private-cli-command-descriptor-owner-implementation-plan.md`
- `proof-binding-authority-hardening-implementation-plan.md`
- `proof-binding-test-inventory-implementation-plan.md`
- `proof-vocabulary-owner-completion-implementation-plan.md`
- `registry-consumer-proof-input-composition-implementation-plan.md`
- `release-authority-typed-projection-implementation-plan.md`
- `release-closeout-proof-discipline-implementation-plan.md`
- `release-platform-matrix-owner-implementation-plan.md`
- `requirement-authoring-plan-implementation-plan.md`
- `requirement-impact-input-compose-implementation-plan.md`
- `requirement-spec-tree-implementation-plan.md`
- `test-inventory-classification-projection-implementation-plan.md`
- `test-inventory-selector-sourcepath-implementation-plan.md`
- `workflow-package-gate-oracle-implementation-plan.md`
- `workspace-manifest-facts-implementation-plan.md`

## Excluded Design Documents

These pre-cutover design documents are not imported wholesale. Their durable
semantics are owned by the current command implementation, tests, specs,
`proofkit/cli-contract.v1.json`, `proofkit/requirement-bindings.json`,
`proofkit/witness-plan.json`, `docs/proofkit-contract-map.md`, `ADOPTION.md`,
`NON_CLAIMS.md`, `docs/release-process.md`, or open backlog rows.

| Group | Category | Current owner surfaces | Non-import reason |
|---|---|---|---|
| Adoption, agent guidance, and scaffolding | represented by current source and open consumer proof rows | `ADOPTION.md`, `docs/proofkit-contract-map.md`, `proofkit/cli-contract.v1.json`, `proofkit/requirement-bindings.json`, `internal/command/adoption*`, `internal/command/agentroute`, `internal/command/gradualadoption`, `internal/command/projectstructure`, `BACKLOG.md` `CONSUMER-01` and `CONSUMER-02` | Old prose mixes implemented provider mechanics with consumer parity and rollout facts; current owner surfaces carry reusable mechanics and backlog rows carry remaining proof. |
| Requirement, proof, coverage, and rendering | represented by current specs, contracts, code, and presentation non-claims | `docs/specs/proofkit-spec-proof-core/requirements.v1.json`, `docs/proofkit-contract-map.md`, `proofkit/requirement-bindings.json`, `proofkit/witness-plan.json`, `internal/command/requirement*`, `internal/command/proof*`, `internal/command/testevidenceinventory`, `internal/command/requirementcoverageview`, `internal/kernel/proofvocab`, `NON_CLAIMS.md` | Durable invariants now live in requirement records, binding rows, tests, and private kernel owners; old design prose would become a parallel contract. |
| Selective planning, receipts, and obligation decisions | represented by current receipt/selective proof owners | `docs/specs/proofkit-receipt-authority/requirements.v1.json`, `docs/proofkit-contract-map.md`, `proofkit/requirement-bindings.json`, `internal/command/selectivegateplan`, `internal/command/selectivegateevidence`, `internal/command/proofreceiptadmission`, `internal/command/receipt*`, `internal/command/obligationdecision`, `internal/kernel/proofvocab` | Current source owns admitted reports and shared proof vocabulary; old design prose is retained only as historical reasoning. |
| Release, deployment, supply chain, and package boundaries | represented by package-public release docs plus open provider rows | `docs/release-process.md`, `docs/specs/proofkit-package-boundary/requirements.v1.json`, `docs/specs/proofkit-supply-chain-quality/requirements.v1.json`, `proofkit/requirement-bindings.json`, `.github/workflows/*`, `internal/tools/*`, `BACKLOG.md` `RELEASE-01` and `SECURITY-01` | Old documents contain stale registry, private-source, and provider-readiness context; current package docs own public release process and backlog rows own unproven provider claims. |
| Migration, workspace, and repository structure | represented by current CLI contract and adoption contract | `ADOPTION.md`, `docs/proofkit-contract-map.md`, `proofkit/cli-contract.v1.json`, `internal/command/migration*`, `internal/command/workspace*`, `internal/command/repoprofileadmission`, `internal/command/impact`, `BACKLOG.md` `CONSUMER-01` and `CONSUMER-02` | Current CLI commands own reusable mechanics; migration and second-consumer adequacy stay open until proven by consumer evidence. |

### Adoption, Agent Guidance, And Scaffolding

- `adoption-checklist-report-design.md`
- `adoption-contract-envelope-admission-design.md`
- `adoption-doctor-design.md`
- `adoption-mode-owner-design.md`
- `adoption-workflow-agent-envelope-design.md`
- `adoption-workflow-authority-routes-design.md`
- `adoption-workflow-contract-envelope-design.md`
- `adoption-workflow-plan-design.md`
- `agent-decision-router-design.md`
- `agent-guidance-envelope-design.md`
- `bootstrap-agent-envelope-design.md`
- `bootstrap-materialization-manifest-design.md`
- `project-structure-agent-envelope-design.md`
- `project-structure-scaffold-design.md`
- `scaffold-profile-plan-design.md`

### Requirement, Proof, Coverage, And Rendering

- `binding-partition-admission-design.md`
- `browser-renderer-consolidation-design.md`
- `compact-proof-contract-projections-design.md`
- `coverage-view-input-compose-design.md`
- `custom-rule-boundary-design.md`
- `proof-binding-authority-hardening-design.md`
- `proof-binding-test-inventory-design.md`
- `proof-obligation-algebra-design.md`
- `proof-receipt-admission-design.md`
- `proof-vocabulary-owner-completion-design.md`
- `requirement-authoring-plan-design.md`
- `requirement-browser-view-design.md`
- `requirement-proof-resolver-projection-design.md`
- `requirement-proof-source-set-design.md`
- `requirement-proof-view-design.md`
- `requirement-source-view-design.md`
- `requirement-spec-tree-design.md`
- `spec-proof-bundle-admission-design.md`
- `test-inventory-and-requirement-coverage-view-design.md`
- `test-inventory-classification-projection-design.md`
- `test-inventory-selector-sourcepath-design.md`
- `witness-scheduler-plan-design.md`

### Selective Planning, Receipts, And Obligation Decisions

- `changed-path-set-agent-envelope-design.md`
- `obligation-decision-agent-envelope-design.md`
- `obligation-decision-state-design.md`
- `producer-policy-self-proof-design.md`
- `receipt-currentness-scope-admission-design.md`
- `receipt-producer-admission-design.md`
- `receipt-trust-class-admission-design.md`
- `selective-evidence-obligation-decision-design.md`
- `selective-evidence-producer-admission-design.md`
- `selective-evidence-receipt-trust-class-design.md`
- `selective-gate-evidence-agent-envelope-design.md`
- `selective-gate-plan-agent-envelope-design.md`
- `selective-planner-edge-coverage-design.md`

### Release, Deployment, Supply Chain, And Package Boundaries

- `admission-diagnostic-hardening-design.md`
- `branch-authority-report-design.md`
- `completion-criteria-report-design.md`
- `deployment-evidence-admission-design.md`
- `json-report-cli-adapter-design.md`
- `package-runtime-dependency-admission-design.md`
- `private-cli-command-descriptor-owner-design.md`
- `registry-consumer-proof-input-composition-design.md`
- `release-authority-typed-projection-design.md`
- `release-closeout-proof-discipline-design.md`
- `release-platform-matrix-owner-design.md`
- `rendered-artifact-freshness-design.md`
- `secret-shaped-json-scan-design.md`
- `supply-chain-quality-hardening-design.md`
- `workflow-package-gate-oracle-design.md`

### Migration, Workspace, And Repository Structure

- `migration-parity-admission-design.md`
- `migration-plan-design.md`
- `requirement-impact-input-compose-design.md`
- `workspace-manifest-facts-design.md`
- `workspace-planning-agent-envelope-design.md`
- `workspace-registry-admission-design.md`

## Open-Work Routing

If a future review proves that an excluded document contains a current durable
invariant not owned by an existing surface, the fix is not to import the old
document unchanged. The fix is one of:

1. add or update a requirement record;
2. add or update a proof binding or witness plan row;
3. add a targeted test or package verification rule;
4. add a concise package-public doc section when consumers need the invariant;
5. add a backlog row with owner, proof path, and release/adoption precondition.

This preserves a single current owner for each invariant and prevents old
implementation prose from becoming a parallel contract.
