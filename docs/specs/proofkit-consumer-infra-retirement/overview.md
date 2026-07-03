# Proofkit Consumer Infrastructure Retirement Spec

This spec owns Proofkit's reusable primitives for retiring duplicated
consumer-side proof infrastructure. It covers migration planning, installed
package runtime dependency admission, workspace registry admission,
repo-profile admission, and adoption workflow routing.
It also covers structured parity evidence admission for repositories that need
machine-checkable preconditions before local proof-owner retirement review.

It is intentionally infrastructure-only. Consumers own old proof surfaces, new
Proofkit inputs, parity evidence, native witness execution, command policy,
receipt freshness, file deletion, CI admission, merge approval, release
approval, rollout approval, and production decisions.

## Requirements

- `REQ-PROOFKIT-RETIRE-001`: migration plans keep old and new proof owners
  explicit and block retirement unless caller-provided parity evidence and
  post-retirement validation commands exist.
- `REQ-PROOFKIT-RETIRE-002`: package runtime dependency admission validates
  caller-provided installed package identity and location facts without reading
  package manager state or resolving packages.
- `REQ-PROOFKIT-RETIRE-003`: workspace registry admission validates
  caller-provided script, dependency, and lockfile facts against caller policy
  without owning repository command policy or lockfile freshness.
- `REQ-PROOFKIT-RETIRE-004`: repo-profile structural and command admission
  validates caller-owned profile, path, command, and environment facts without
  scanning repositories or approving native proof coverage.
- `REQ-PROOFKIT-RETIRE-005`: adoption workflow plans route legacy migration,
  gradual adoption, and release-channel scenarios to existing Proofkit
  primitives through bounded structured command refs.
- `REQ-PROOFKIT-RETIRE-006`: migration parity admission validates
  caller-provided parity evidence shape, source/target closure, typed
  equivalence dimensions, and matched digest equality without owning evidence
  authenticity, freshness, semantic correctness, or retirement approval.
- `REQ-PROOFKIT-RETIRE-007`: gradual adoption guidance keeps caller-provided
  candidate boundaries advisory, exposes owner-review questions, routes mode
  and checked-scope semantics through one private owner, and fails closed for
  enforcement modes until the consumer admits stable requirements and proof
  bindings.
- `REQ-PROOFKIT-RETIRE-008`: adoption doctor reports classify caller-provided
  imperfect-repository migration gaps and non-passing child reports into
  advisory, failed, or blocked states and emit bounded owner-specific guidance
  without scanning repositories or owning semantic boundary decisions.
- `REQ-PROOFKIT-RETIRE-009`: workspace manifest fact projection turns explicit
  caller-owned manifest records into registry-compatible workspace facts and
  planning inputs without reading manifests from disk or owning package-manager
  policy.
- `REQ-PROOFKIT-RETIRE-010`: registry consumer proof input composition turns
  explicit caller-owned registry metadata, registry pack comparison, lock,
  smoke, rollback, precondition, and release-authority facts into a
  `registry-consumer` input only when those facts are complete and aligned,
  while preserving `registry-consumer` as the final proof-schema owner.

## Non-Claims

- This spec does not authorize deletion of consumer files or local proof owners.
- This spec does not execute commands, authenticate parity evidence, compute
  proof freshness, or approve merge.
- This spec does not make Proofkit a repository scanner, command-policy owner,
  CI authority, release authority, rollout authority, or production-readiness
  authority for consumers.
