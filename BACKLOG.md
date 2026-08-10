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
| NEXT | COVERAGE-01 | Replace command proof-route candidates with an owner-admitted executable oracle ledger; static route records are explicitly non-semantic. | `CommandCoverageInventory` consumes a separate execution-backed owner ledger whose rows bind `commandRef`, selector, concrete falsification event, assertion oracle, expected public outcome, and owner invariant; an independently authored versioned counterfeit corpus covers every shipped policy, evidence class, identity coordinate, and single or correlated substitution axis with positive controls and exact expected decisions; until then route metadata, prose, legacy source markers, test existence, and failure-capable AST nodes emit only declared routes or `proof_route_candidate`, candidate-route closure remains blocking, and semantic execution evidence remains an explicit non-claim. |
| NEXT | COMPACT-01 | Replace compact proof caller labels and synthetic counts with an honest declaration-only schema/profile. | One atomic schema/profile cutover prefixes caller-owned proof and mutation fields with `declared`, removes checked/finding counts without independent evidence owners, rejects collapsed witness roles, updates every compact producer and consumer, and proves exact role and round-trip closure without claiming execution or assurance. |
| NEXT | SOURCE-MODEL-01 | Define one representation-neutral typed requirement-source v2 model before selecting a source syntax. | A private bounded model admits atomic requirement identities, grouped authoring, premises, scenarios, definitions, vocabulary, lifecycle, references, and deterministic normalization; an independently authored field/variant completeness manifest plus mutant corpus proves every normative field reaches each required downstream owner, with no production parser or persisted normalized mirror. |
| BLOCKED | SOURCE-CODEC-01 | Select at most one compact source codec without creating dual authority. | After `SOURCE-MODEL-01`, one versioned experiment manifest freezes disjoint role sets: the flat-v1 baseline control, grouped-model ablations, and exactly complete grouped-JSON plus at most one complete restricted-DSL codec candidate over the same model. Only codec candidates can win the predeclared replacement relation; controls and ablations measure causality and cannot become production grammars. A newly discovered candidate requires a new manifest version and complete experiment. A frozen corpus and strict `Replace(candidate, grouped-json)` predicate cover grammar completeness, safety, semantic parity, diagnostics, canonical bytes, review accuracy, token cost, diff amplification, parse/format cost, and unknowns. Every metric is classified exactly once by a versioned registry with role, direction, baseline pair, aggregation, material threshold, primary decision requirement, and missing-observation semantics; duplicate or unclassified metrics fail admission, hard constraints cannot trade off, report-only metrics cannot decide replacement, promised byte/token reductions must be materially better, and bounded diff/parse costs must be noninferior. If grouped JSON fails its hard gate, retain the current flat v1 source and perform no v2 cutover; otherwise select the restricted text candidate only when it is the unique strict replacement, while a tie, unknown, incomparability, or non-material improvement selects grouped JSON. The losing parser and formatter are deleted before experiment closeout, and production admits exactly one grammar. |
| BLOCKED | SOURCE-CUTOVER-01 | Migrate self-hosted requirement sources only after one codec, the typed v2 model, nested structural contracts, and the complete evidence counterfeit corpus pass their gates. | `COVERAGE-01` and `SCHEMA-01` are complete; a digest-bound clause ledger proves representation-only equality or owner-reviewed semantic decomposition for every legacy requirement; all bindings/scenarios/contracts/context/diff/graph/browser owners cut over atomically; v1 admission and the losing codec are removed; and active-v1 inventory is zero. |
| BLOCKED | SCHEMA-01 | Replace root-shape-only public contracts with one independent complete nested structural-contract owner. | A versioned schema owner covers nested fields, variants, cardinalities, bounds, enums, defaults, duplicate and unknown-field policy, and cross-field constraints; generated artifacts pass parity against an independently authored completeness manifest and mutant corpus without becoming semantic or policy authority. |
| BLOCKED | SOURCE-PILOT-01 | Validate the selected source-v2 model and agent routing against heterogeneous external repositories without mutating them. | At least two independent repository classes complete no-push dual runs whose frozen inputs compare incumbent and candidate mapping, diagnostics, token cost, authoring accuracy, proof-route gaps, and rollback; unresolved parity or authority gaps keep incumbent owners active. |
| BLOCKED | GOVERNANCE-01 | Evaluate a generic explicit-inventory governance-observation command without promoting one consumer's policy into Proofkit; detailed candidate contract is retained in [issue #64](https://github.com/research-engineering/agentic-proofkit/issues/64). | A sanitized reproducible fixture detects one named failure without classifying its false-positive counterexample, existing owners are proven insufficient, and either a second independent consumer reproduces the predicate or the owner admits recurring first-consumer cost; otherwise retire the candidate. |
| DEFERRED | VALUE-01 | Admit exact value-evidence comparisons only after a real producer and downstream consumer establish the public record boundary; detailed candidate contract is retained in [issue #65](https://github.com/research-engineering/agentic-proofkit/issues/65). | A real execution-receipt projection, baseline producer, and downstream consumer prove an exact producer-output-to-admission round trip plus compact/full-graph inclusion or an intentional omission non-claim; otherwise no public command is added. |
| BLOCKED | RELOCATION-01 | Add provenance-bounded witness relocation candidates without introducing a second binding path or trusting a caller-authored prior digest; detailed candidate contract is retained in [issue #66](https://github.com/research-engineering/agentic-proofkit/issues/66). | An owner-admitted content-addressed baseline binds witness id, prior path and digest, source revision, evidence class, authentication non-claims, and freshness non-claims; the scanner then proves the zero/one/many match partition while remaining non-current until fresh execution evidence exists. |
| BLOCKED | RELEASE-01 | Prove signed protected-tag release policy as provider-side release governance, not source-only intent. | Repository tag protection/ruleset and release workflow variables require signed annotated release tags; the next public release records provider-side evidence or the row is explicitly retired as an accepted non-claim. |
| BLOCKED | RELEASE-02 | Retire the inaccurate PyPI `0.1.159` wheel compatibility and license projection without mutating immutable release history. | After a public replacement release proves macOS 12.0 wheel tags, embedded MIT license identity, npm/PyPI/GitHub byte closure, and installed-package smoke, yank PyPI `0.1.159` with an exact compatibility-and-license reason and retain provider evidence of the yank. |
