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
| NEXT | COVERAGE-01 | Strengthen command semantic coverage so `semantic_falsifier` cannot be satisfied by route metadata, prose rationale, test-function existence, or a weak same-package smoke. | Command coverage emits and counts `semantic_falsifier` only from an owner-authored executable proof identity that binds `commandRef`, selector, negative case, oracle ID, and expected public outcome. Add regression tests rejecting unrelated existing tests, assertionless or skipped tests, route-index/prose-synthesized proof IDs, and metadata-only semantic routes; keep route-only discovery as non-claim evidence. |
| BLOCKED | RELEASE-01 | Decide whether normalized post-create GitHub Release facts need durable public evidence beyond retained workflow artifacts under immutable GitHub Releases. | Either keep `github-release.json` as retained workflow evidence with explicit non-claims, or design a provider-compatible public evidence channel that does not require post-create Release asset mutation. Completion requires a release-proof design and live provider proof; direct backfill/upload is blocked by immutable Release upload rejection. |
| BLOCKED | RELEASE-02 | Resolve or explicitly retire the immutable historical GitHub Release asset-closure gap where release metadata references a notes asset that the published release does not contain. | Either attach the exact checksum-matching notes asset if provider policy allows, or record the provider-impossible closure in the release evidence model and prove future releases cannot repeat the gap. Completion requires live provider proof; direct backfill is currently blocked by immutable Release upload rejection. |
| NEXT | RECEIPT-01 | Split the aggregate self-hosting package receipt only if Go and Python package evidence can be admitted as independent evidence classes without losing package-gate closure. | Either emit separate Go and Python receipt kinds with independent command, artifact, environment, and producer-admission projections, or retain the aggregate `local-go-python` receipt with explicit non-claims and no split-readiness claim. Add receipt-producer and self-hosting regression tests for whichever model is admitted. |
