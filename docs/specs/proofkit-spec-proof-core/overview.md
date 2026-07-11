# Proofkit Spec-Proof Core Spec

This spec owns Proofkit's reusable spec-to-proof primitives: requirement source
admission, requirement proof bindings, witness planning, selective proof
planning, selective evidence admission, rendered proof views, and bounded agent
envelopes.

It is intentionally infrastructure-only. Consumers provide requirement
sentences, proof bindings, changed-path facts, command policy, native witnesses,
execution receipts, and merge policy.

## Requirements

- `REQ-PROOFKIT-SPEC-001`: requirement source admission validates structured
  `REQ-*` records and source-package shape without owning requirement meaning
  or scanning overview prose as authority.
- `REQ-PROOFKIT-SPEC-002`: requirement proof binding reports validate
  caller-owned requirement-to-witness mappings, require compact scenarios to be
  admitted `surface_id::stable_anchor` identities, require compact witness
  selectors to use `repo/path::stable_anchor` identities, admit caller-owned
  source-set fragments and selected-source resolver projections, and derive
  typed compact proof contract projections for surfaces, scenarios, witnesses,
  commands, environment classes, conformance facts, and falsification routes
  without executing witnesses or deciding proof freshness.
- `REQ-PROOFKIT-SPEC-003`: witness planning accepts caller-owned structured
  command metadata, scheduler constraints, environment classes, and
  binding-derived command projections only through admitted witness vocabulary
  and conservative safe argv policy, without executing commands or selecting
  repository policy.
- `REQ-PROOFKIT-SPEC-004`: selective planning and selective evidence reports
  keep changed-path facts, planned commands, receipts, evidence class,
  producer-admission state, and obligation candidates explicit, keep merge
  approval consumer-owned, and fail closed for unknown or unmatched proof
  inputs.
- `REQ-PROOFKIT-SPEC-005`: rendered proof views and agent envelopes remain
  bounded, derived presentations over structured source and never become
  canonical proof or requirement authority.
- `REQ-PROOFKIT-SPEC-006`: test evidence inventory, explicit test-discovery
  draft projections, proof-binding-derived inventory projections, normalized
  inventory projections, coverage-view input composition, and requirement
  coverage views classify or assemble caller-owned test-to-requirement,
  command, witness, owner-invariant, quality-finding, and declared-surface
  routes, preserve source-set entry provenance, fail closed on structured
  selector/sourcePath drift, command-ref collisions, missing requirement
  owners, scope widening, fabricated normalized inventory, non-strict
  discovery candidate inventory, nonsemantic command evidence, and declared
  dead zones in selected-owner or full-repository scopes, and do not treat
  proof routes, discovery drafts, nonsemantic command evidence, normalized
  projections, composed inputs, or rendered views as semantic test coverage.
- `REQ-PROOFKIT-SPEC-007`: caller-owned inputs are admitted into canonical
  immutable records before any proof, policy, route, rendering, or report
  decision consumes them.
- `REQ-PROOFKIT-SPEC-008`: requirement spec tree admission validates explicit
  caller-owned spec hierarchy, source-reference modes, digest facts, overlay
  refs, deterministic output, and tree topology without scanning repositories,
  reading sources, rendering views, or owning requirement/proof semantics.
- `REQ-PROOFKIT-SPEC-009`: requirement spec tree views render admitted
  caller-owned hierarchy through shared safe browser document fragments,
  deterministic CLI JSON, Markdown, HTML, explicit output paths, and loopback
  browser serving without accepting caller-owned raw HTML or making rendered
  output authoritative.
- `REQ-PROOFKIT-SPEC-010`: requirement impact input composition converts
  caller-owned base/current requirement sources, single-current-binding compact
  proof contracts, changed-path facts, generated-artifact policy, local
  environment policy, and proof-like path policy into a direct `impact` input
  without scanning repositories, executing witnesses, or becoming a second
  impact evaluator.
- `REQ-PROOFKIT-SPEC-011`: adoption contract envelope admission validates a
  complete caller-owned aggregate adoption envelope, selects one child route
  through orthogonal CLI flags, and delegates to existing child command
  contracts without becoming a second adoption readiness policy.
- `REQ-PROOFKIT-SPEC-012`: requirement authoring plans package caller-provided
  design, implementation, PR, code, test, and clarification facts into
  candidate-only requirement updates, delegate structural checks to requirement
  source admission and transition, and keep owner review/materialization outside
  Proofkit.
- `REQ-PROOFKIT-SPEC-013`: repeated cross-command proof vocabulary has one
  private owner for proof and selective-edge state while command-local and
  caller-owned vocabularies stay outside the shared owner.
- `REQ-PROOFKIT-SPEC-014`: document lifecycle boundary reports classify
  caller-owned document lifecycle metadata so temporary, historical, generated,
  rendered, router, work-ledger, and durable documents cannot silently retain
  the wrong authority role.
- `REQ-PROOFKIT-SPEC-015`: spec overview claim reports validate
  caller-provided overview claim extraction facts so durable overview claims
  cite known requirement records and non-durable claims remain non-normative.
- `REQ-PROOFKIT-SPEC-016`: requirement source transition reports validate
  caller-provided previous and next source snapshots so lifecycle changes are
  monotonic, evidence-backed, package-boundary-stable, and repository-neutral.
- `REQ-PROOFKIT-SPEC-017`: capability map admission validates caller-owned
  pre-spec observations under explicit code-baseline or code-audit trust modes
  and emits only bounded candidate requirements, bindings, or owner guidance.
- `REQ-PROOFKIT-SPEC-018`: an authored command-family catalog covers every
  public CLI command exactly once, deterministically generates the private
  runtime navigation projection, and adds opt-in family help without changing
  root help, per-command help, or leaf dispatch.

## Non-Claims

- This spec does not claim consumer repository adoption.
- This spec does not claim native witness execution.
- This spec does not authenticate receipt producers or compute proof freshness.
- This spec does not approve merge, release, registry publication, rollout, or
  production readiness.
- This spec does not approve document deletion or infer document meaning from
  Markdown prose.
- This spec does not prove overview-claim extractor completeness.
- This spec does not discover source diffs or approve requirement deletion.
