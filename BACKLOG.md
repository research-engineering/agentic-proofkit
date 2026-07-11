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
| NEXT | COVERAGE-01 | Replace command proof-route candidates with an owner-admitted executable oracle ledger; static route records are explicitly non-semantic. | `CommandCoverageInventory` consumes a separate execution-backed owner ledger whose rows bind `commandRef`, selector, concrete falsification event, assertion oracle, expected public outcome, and owner invariant; until then route metadata, prose, source markers, test existence, and failure-capable AST nodes emit only `proof_route_candidate`, candidate-route closure remains blocking, and missing `semantic_falsifier` evidence remains an explicit non-blocking metric and non-claim. |
| BLOCKED | GOVERNANCE-01 | Evaluate a generic explicit-inventory governance-observation command without promoting one consumer's policy into Proofkit; detailed candidate contract is retained in [issue #64](https://github.com/research-engineering/agentic-proofkit/issues/64). | A sanitized reproducible fixture detects one named failure without classifying its false-positive counterexample, existing owners are proven insufficient, and either a second independent consumer reproduces the predicate or the owner admits recurring first-consumer cost; otherwise retire the candidate. |
| DEFERRED | VALUE-01 | Admit exact value-evidence comparisons only after a real producer and downstream consumer establish the public record boundary; detailed candidate contract is retained in [issue #65](https://github.com/research-engineering/agentic-proofkit/issues/65). | A real execution-receipt projection, baseline producer, and downstream consumer prove an exact producer-output-to-admission round trip plus compact/full-graph inclusion or an intentional omission non-claim; otherwise no public command is added. |
| BLOCKED | RELOCATION-01 | Add provenance-bounded witness relocation candidates without introducing a second binding path or trusting a caller-authored prior digest; detailed candidate contract is retained in [issue #66](https://github.com/research-engineering/agentic-proofkit/issues/66). | An owner-admitted content-addressed baseline binds witness id, prior path and digest, source revision, evidence class, authentication non-claims, and freshness non-claims; the scanner then proves the zero/one/many match partition while remaining non-current until fresh execution evidence exists. |
| BLOCKED | RELEASE-01 | Prove signed protected-tag release policy as provider-side release governance, not source-only intent. | Repository tag protection/ruleset and release workflow variables require signed annotated release tags; the next public release records provider-side evidence or the row is explicitly retired as an accepted non-claim. |
