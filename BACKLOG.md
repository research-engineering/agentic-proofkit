# Proofkit Backlog

This file is the canonical active-work ledger for
`research-engineering/agentic-proofkit`.

It tracks only current `NEXT`, `BLOCKED`, or `DEFERRED` work. It is not a
roadmap, release log, proof registry, architecture document, CLI manual, or
historical completion archive.

## Current State

Active work is limited to the rows below.

The public source cutover, scoped npm channel, optional PyPI channel, provider
security setup, first-consumer proof, and second-consumer pilot have all been
closed. Durable rules and reusable architecture now live in their owner
surfaces:

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
| NEXT | COVERAGE-01 | Strengthen command coverage so `semantic_falsifier` cannot be satisfied by route metadata plus a generic non-empty Go test body. | Command coverage routes must bind to an owner-admitted executable oracle ledger or native test inventory that proves the command ref, negative case, expected public outcome, and assertion owner are the same fact. Completion requires `self:coverage` to reject a route whose test exists and has assertions but whose admitted oracle is unrelated to the command invariant. |
| NEXT | SOURCESET-01 | Consolidate normalized test-evidence source-set provenance admission into one owner-owned projection shared by coverage input composition and coverage view admission. | A single internal projection API must admit `normalizedTestEvidenceInventory`, return the canonical envelope plus nested direct inventory, and be reused by `requirement-coverage-input-compose` and `requirement-coverage-view`. Completion requires parity tests proving source-set provenance cannot be accepted by one path while being lost or interpreted differently by another. |
| DEFERRED | REDACTION-01 | Replace duplicated generated TypeScript redaction taxonomy with a shared generated contract or parity fixture derived from the Go admission owner. | Generated adapter redaction must be proven against the same secret/control taxonomy as Go report-visible admission without hand-maintained regex drift. Completion requires a parity test that fails when a secret-like class is added to Go admission but omitted from generated TypeScript formatting. |
| BLOCKED | RELEASE-01 | Decide whether normalized post-create GitHub Release facts need durable public evidence beyond retained workflow artifacts under immutable GitHub Releases. | Either keep `github-release.json` as retained workflow evidence with explicit non-claims, or design a provider-compatible public evidence channel that does not require post-create Release asset mutation. Completion requires a release-proof design and live provider proof; direct backfill/upload is blocked by immutable Release upload rejection. |
| BLOCKED | RELEASE-02 | Resolve or explicitly retire the immutable historical GitHub Release asset-closure gap where release metadata references a notes asset that the published release does not contain. | Either attach the exact checksum-matching notes asset if provider policy allows, or record the provider-impossible closure in the release evidence model and prove future releases cannot repeat the gap. Completion requires live provider proof; direct backfill is currently blocked by immutable Release upload rejection. |
