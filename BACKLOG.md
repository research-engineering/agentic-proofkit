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
- `docs/specs/**/requirements.v2.json` for durable machine requirements;
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
| NEXT | BROWSER-TOOLCHAIN-01 | Qualify a stable browser-test successor to the pinned 1.63.0 SDK without the native WebKit select/CSP regression first shipped in 1.64.0: its WebKit sets a style attribute on a select element's internal slot before that slot is in the user-agent shadow tree, so the page's `style-src` refuses it and logs a console error. | Preserve native navigation, exact engine evidence, strict CSP and zero retries in the complete Chromium, Firefox and WebKit gate. Decide from repeated complete Firefox runs whether site-origin process isolation remains required (1.62.1 failed without it; one 1.63.0 run passed without it); update its fixture and contributor explanation together with any policy change. Do not substitute a custom engine or ignore console/security-policy failures. |
| BLOCKED | SCHEMA-01 | Prove the completeness of the versioned nested structural contracts that replaced the root-shape-only public contracts. | An independently authored completeness manifest enumerates every published direction and variant and records, per direction, which cardinality, bound, enum, default, duplicate, unknown-field and cross-field constraints its schema expresses and which remain native-owned non-claims; the published schemas pass parity against that manifest and a mutant corpus without becoming semantic or policy authority. |
| NEXT | SOURCE-CONVERSION-01 | Close the residual review and installed-carrier evidence for `requirement-source-conversion` (`REQ-PROOFKIT-SPEC-044`): grouped v2 export to a complete flat v1 document, digest-bound baseline import of value edits only, and refusal of the retired flat v1 source. | Independent review admits the recorded format, preservation, ownership, legacy-v1 and future-adapter decisions in the spec-proof-core requirement and overview; the publishable closeout gate runs on the final committed object, including `package:artifact` and the provider carrier jobs, so the installed npm and wheel carriers execute the shared conversion smoke on that object; then remove this row. A DSL adapter is not part of this row and needs its own admission under the documented boundary. |
| BLOCKED | GOVERNANCE-01 | Evaluate a generic explicit-inventory governance-observation command without promoting one consumer's policy into Proofkit; detailed candidate contract is retained in [issue #64](https://github.com/research-engineering/agentic-proofkit/issues/64). | A sanitized reproducible fixture detects one named failure without classifying its false-positive counterexample, existing owners are proven insufficient, and either a second independent consumer reproduces the predicate or the owner admits recurring first-consumer cost; otherwise retire the candidate. |
| DEFERRED | VALUE-01 | Admit exact value-evidence comparisons only after a real producer and downstream consumer establish the public record boundary; detailed candidate contract is retained in [issue #65](https://github.com/research-engineering/agentic-proofkit/issues/65). | A real execution-receipt projection, baseline producer, and downstream consumer prove an exact producer-output-to-admission round trip plus compact/full-graph inclusion or an intentional omission non-claim; otherwise no public command is added. |
| BLOCKED | RELOCATION-01 | Add provenance-bounded witness relocation candidates without introducing a second binding path or trusting a caller-authored prior digest; detailed candidate contract is retained in [issue #66](https://github.com/research-engineering/agentic-proofkit/issues/66). | An owner-admitted content-addressed baseline binds witness id, prior path and digest, source revision, evidence class, authentication non-claims, and freshness non-claims; the scanner then proves the zero/one/many match partition while remaining non-current until fresh execution evidence exists. |
