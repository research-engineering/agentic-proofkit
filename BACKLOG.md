# Proofkit Backlog

This file is the canonical active-work ledger for
`research-engineering/agentic-proofkit`.

It tracks only current `NEXT`, `BLOCKED`, or `DEFERRED` work. It is not a
roadmap, release log, proof registry, architecture document, CLI manual, or
historical completion archive.

## Current State

Active work is limited to the rows below. Durable rules and reusable
architecture live in their owner surfaces:

- `README.md` for human orientation;
- `ADOPTION.md` for adoption, distribution, rendering, requirement, contract,
  test, and agent-guidance models;
- `NON_CLAIMS.md` for boundary denials;
- `docs/proofkit-contract-map.md` for command-family routing and agent
  decision procedure;
- `docs/release-process.md` for release-channel evidence and publication
  process;
- `docs/specs/**/requirements.v1.json` for durable machine requirements;
- `proofkit/*.json` for shipped machine contracts and proof routes;
- source, tests, package metadata, and workflows for executable behavior.

## Admission Rules

Add a row only when new work is accepted and cannot be represented more
precisely by an existing owner surface.

Every row must be falsifiable and include:

- `Status`: `NEXT`, `BLOCKED`, or `DEFERRED`;
- `ID`: stable owner-scoped identifier;
- `Scope`: one bounded reason to change;
- `Completion condition`: objective proof or explicit retirement condition.

When a row is completed, remove it from this active backlog after its durable
rule, evidence, or behavior is represented by the owning source, test,
contract, release artifact, provider record, or documentation surface. Do not
retain completed rows here as history.

Historical evidence belongs in pull requests, release artifacts, registry
records, generated release manifests, or the owning docs named above.

## Open Rows

| Status | ID | Scope | Completion condition |
|---|---|---|---|
| BLOCKED | SOURCE-CUTOVER-01 | Migrate self-hosted requirement sources only after one codec, the typed v2 model, nested structural contracts, and the complete evidence counterfeit corpus pass their gates. | The `REQ-PROOFKIT-QUALITY-010` execution-backed command-oracle closure and `SCHEMA-01` are complete; a digest-bound clause ledger proves representation-only equality or owner-reviewed semantic decomposition for every legacy requirement; all bindings/scenarios/contracts/context/diff/graph/browser owners cut over atomically; v1 admission and the losing codec are removed; and active-v1 inventory is zero. |
| BLOCKED | SCHEMA-01 | Replace root-shape-only public contracts with one independent complete nested structural-contract owner. | A versioned schema owner covers nested fields, variants, cardinalities, bounds, enums, defaults, duplicate and unknown-field policy, and cross-field constraints; generated artifacts pass parity against an independently authored completeness manifest and mutant corpus without becoming semantic or policy authority. |
| BLOCKED | SOURCE-PILOT-01 | Validate the selected source-v2 model and agent routing against heterogeneous external repositories without mutating them. | At least two independent repository classes complete no-push dual runs whose frozen inputs compare incumbent and candidate mapping, diagnostics, token cost, authoring accuracy, proof-route gaps, and rollback; unresolved parity or authority gaps keep incumbent owners active. |
| BLOCKED | GOVERNANCE-01 | Evaluate a generic explicit-inventory governance-observation command without promoting one consumer's policy into Proofkit; detailed candidate contract is retained in [issue #64](https://github.com/research-engineering/agentic-proofkit/issues/64). | A sanitized reproducible fixture detects one named failure without classifying its false-positive counterexample, existing owners are proven insufficient, and either a second independent consumer reproduces the predicate or the owner admits recurring first-consumer cost; otherwise retire the candidate. |
| DEFERRED | VALUE-01 | Admit exact value-evidence comparisons only after a real producer and downstream consumer establish the public record boundary; detailed candidate contract is retained in [issue #65](https://github.com/research-engineering/agentic-proofkit/issues/65). | A real execution-receipt projection, baseline producer, and downstream consumer prove an exact producer-output-to-admission round trip plus compact/full-graph inclusion or an intentional omission non-claim; otherwise no public command is added. |
| BLOCKED | RELOCATION-01 | Add provenance-bounded witness relocation candidates without introducing a second binding path or trusting a caller-authored prior digest; detailed candidate contract is retained in [issue #66](https://github.com/research-engineering/agentic-proofkit/issues/66). | An owner-admitted content-addressed baseline binds witness id, prior path and digest, source revision, evidence class, authentication non-claims, and freshness non-claims; the scanner then proves the zero/one/many match partition while remaining non-current until fresh execution evidence exists. |
| BLOCKED | RELEASE-01 | Prove signed protected-tag release policy as provider-side release governance, not source-only intent. | Repository tag protection/ruleset and release workflow variables require signed annotated release tags; the next public release records provider-side evidence or the row is explicitly retired as an accepted non-claim. |
| DEFERRED | CLI-ARGS-01 | Evaluate one immutable typed parse result between descriptor admission and command execution instead of independently interpreting already-admitted command operands. | A reproducible descriptor-versus-handler drift falsifier establishes the defect class; a bounded prototype proves exact flag, multiplicity, value, help, input, and presentation parity across every affected command with no new ambient authority or generic option bag; otherwise retain the current bounded parsers and retire the row. |
| DEFERRED | WEB-PUBLISH-DESIGN-01 | Investigate optional publication of the specification browser at a configurable domain with authentication. Preserve local loopback serving and local browser opening as the default workflow; remote publication must be explicit and opt-in. | After the current program, compare static export with external hosting, a bounded deployment adapter, and an authenticated hosted server. Decide whether any capability belongs in Proofkit or should remain external, using a concrete consumer need and maintenance/security costs. The decision must define URL and authentication configuration, hosting/TLS/access-control ownership, source-disclosure and secret boundaries, content freshness, and preservation of derived-view authority. Require a feasibility witness and negative cases for unauthorized access and unintended publication before accepting an implementation plan; otherwise retain local-only behavior and retire the candidate with rationale. This row authorizes investigation, not exposure of the current server or deployment. |
| DEFERRED | TRACEABILITY-DESIGN-01 | Design and validate the complete specification, scenario, native-test and execution-evidence workflow, including source intake, change impact and explanatory diagrams; see the bounded questions below. Start after the already scheduled global phases and existing backlog tasks are completed or explicitly dispositioned. | An owner-reviewed design and implementation decision resolves every question below against current Proofkit, StrictDoc and OpenSpec capabilities; an executable example and adversarial controls justify the selected ownership, storage and invalidation model. Existing mechanisms are reused when sufficient; unsupported additions are explicitly rejected rather than assumed necessary. |

## TRACEABILITY-DESIGN-01

This is deferred design work, not a claim that the following capabilities are
implemented or absent. First establish the current behavior and reuse existing
owners before proposing a new command, record, parser or workflow engine.

### Questions And Acceptance Evidence

- **Source intake.** Evaluate requirements derived from existing code, an
  external specification, design and implementation-plan documents, tests and
  test-coverage observations, or explicit product intent. Preserve provenance,
  assumptions and unresolved contradictions. Distinguish an explicit
  code-as-baseline mode from an audit-from-code mode. A bounded, explicitly
  selected code scan and assisted specification authoring must not be confused
  with the current recognized-file scan or with automatic owner acceptance.
- **Normative authority.** Keep one editable owner of each behavioral promise.
  Generated candidates require owner review before becoming specifications;
  tests and observed implementation behavior cannot silently redefine them.
- **Complete chain.** Evaluate stable requirement ID -> scenario ID -> native
  witness/path/selector -> command/environment -> actual result -> coverage.
  Check both directions, many-to-many relationships, discovered-but-unmapped
  tests, dangling references, parametrized tests, explicit exclusions and
  missing, skipped or stale execution. A link is not an adequate oracle.
- **Change propagation.** For a semantic change anywhere in the chain, derive
  the affected dependency closure and automatically require confirmation or
  update of affected specifications, scenarios, tests, bindings and evidence.
  Changes to tests must trigger upstream impact review, not automatic rewriting
  of the specification. Distinguish semantic from presentation-only changes;
  preserve unaffected approvals and bind confirmations to exact current
  subjects. Exercise additions, removals, renames, changed assertions,
  environment changes and stale confirmations without forcing cosmetic edits.
- **Scenario storage decision.** Compare separate scenario documents, scenarios
  in the specification, structured declarations in test files, and test-adjacent
  comments or annotations parsed into a derived inventory. Justify whether an
  intermediate scenario document has independent meaning worth maintaining.
  Preserve stable IDs, machine readability, native discovery, browser rendering,
  cross-language portability and one editable source. Measure authoring, token,
  review, drift, parser and maintenance cost rather than selecting by aesthetics.
- **Agent guidance and cookbook.** Check that the agent receives actionable,
  bounded instructions and a template for repository-specific discovery,
  bindings, executable checks and evidence admission. Add or repair a complete
  cookbook example only where the current documentation is insufficient. Show
  a positive control, a behavior-breaking near miss, an unmapped or missing
  test, and stale evidence; do not fabricate test completeness.
- **Diagrams and explanation.** Audit README, adoption guidance, reference and
  cookbook coverage for two understandable visual routes: multiple candidate
  sources -> invariant extraction -> owner review -> canonical specification;
  and specification -> scenario -> native test -> command/environment -> result
  and coverage. Explain reverse impact review separately from forward proof
  flow. Link each explanation to its current contract owner and validate actual
  rendering; diagram count alone is not a completeness metric.
- **Migration and alternatives.** Compare the same workflow with StrictDoc,
  including its DSL and test-report integration, and OpenSpec. Run a bounded
  example in which the same externally observable scenarios exercise both a
  TypeScript implementation and a Python/FastAPI replacement. Keep requirement
  and scenario IDs while allowing native adapters to differ. Passing selected
  scenarios does not prove equivalence for every possible behavior.
- **Decision closure.** Document why the chosen structure is preferable to the
  strongest lower-cost alternative, including retaining the current structure
  when sufficient. Keep the durable rationale in the narrowest appropriate
  explanation or contract owner. Implement only admitted gaps, with negative
  whole-chain tests, honest non-claims and measured cost; do not create a second
  normative scenario store or an unjustified universal test engine.
