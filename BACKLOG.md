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
| NEXT | COVERAGE-01 | Upgrade command semantic coverage from route-authored proof metadata to an owner-admitted executable oracle ledger. | `CommandCoverageInventory` consumes a separate source-owned oracle ledger whose rows bind `commandRef`, selector, negative case, assertion oracle, expected public outcome, and owner invariant; route metadata alone cannot emit `semantic_falsifier`; `npm run self:coverage` and targeted negative fixtures prove weak/no-op route tests stay non-semantic. |
| BLOCKED | RELEASE-01 | Prove signed protected-tag release policy as provider-side release governance, not source-only intent. | Repository tag protection/ruleset and release workflow variables require signed annotated release tags; the next public release records provider-side evidence or the row is explicitly retired as an accepted non-claim. |
