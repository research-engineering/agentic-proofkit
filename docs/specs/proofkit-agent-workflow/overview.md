# Proofkit Agent Workflow Spec

This spec owns Proofkit's generic support for planning one engineering-change
snapshot and for teaching a consuming repository to define executable native
evidence. It does not own consumer product meaning, repository policy,
witnesses, merge, release, rollout, or production-readiness decisions.

The public capability is deliberately small:

1. `change-workflow-plan` admits explicit JSON and projects one next action for
   the optional built-in profile `proofkit.reviewed-change.v1`, whose ordered
   stages are `architecture`, `design`, `implementation_plan`,
   `implementation`, `verification`, `pull_request`, and `closeout`.
2. `native-evidence-guidance` exposes one versioned 22-slot template for
   repository-owned falsifiers, oracles, bounds, lifecycle, and non-claims.
   Every slot names one closed applicability class: `always`,
   `declared_input_channels`, `environment_or_network_access`,
   `external_process`, or `mutable_artifacts`. The latter four apply only when
   the consuming witness declares the named mechanism.
3. Existing descriptors, dispatch, command families, root-shape CLI contracts,
   agent envelopes, and package gates provide public-surface closure.

Neither command scans a repository. Both command cores are stateless pure
projections with no filesystem, Git, process, environment, clock, random,
network, container, or provider dependency. No setup facade, agent-route extension,
external prompt resource, persisted experiment state, or second source codec is
introduced.

## Requirements

- `REQ-PROOFKIT-WORKFLOW-001`: one-time typed admission, pure deterministic
  projection, and derived-output authority boundary.
- `REQ-PROOFKIT-WORKFLOW-002`: named optional built-in profile, exact
  seven-stage order, prefix/checkpoint biconditional, and a disjoint terminal
  output.
- `REQ-PROOFKIT-WORKFLOW-003`: 28 active state rows, one terminal row, an
  executable envelope transition for every accepted stage, and an explicit
  terminal stop packet.
- `REQ-PROOFKIT-WORKFLOW-004`: typed subject/finding resolution and internally
  consistent caller-declared digests.
- `REQ-PROOFKIT-WORKFLOW-005`: shared 256-byte stable-ID admission before work,
  global candidate-dependency resolution, one explicit nullable
  governing-authority reference, role-preserving bounded least dependency
  closure over explicit seeds, exact omission accounting, and output-byte
  limits.
- `REQ-PROOFKIT-WORKFLOW-006`: only existing launcher and presentation
  capabilities outside explicit input, with no ambient repository authority,
  setup facade, hidden policy, or agent-route extension.
- `REQ-PROOFKIT-WORKFLOW-007`: pure deterministic repository-neutral
  native-evidence guidance from one versioned typed table with five closed
  applicability classes, explicit absent-channel decisions, and finite
  nondisclosure corpora.
- `REQ-PROOFKIT-WORKFLOW-008`: display-safe caller admission, no-leak denial,
  bounded actionable text with required coordinates, and no styling of caller
  values.
- `REQ-PROOFKIT-WORKFLOW-009`: explicit text/color selection and confinement of
  ANSI to eligible terminal stdout.
- `REQ-PROOFKIT-WORKFLOW-010`: one production owner per semantic relation,
  independently authored semantic oracles, and an AST-checked two-command
  carrier topology with no runtime experiment or external template residue.
- `REQ-PROOFKIT-WORKFLOW-011`: a finite factorized CLI relation closed across
  descriptor/dispatcher/family/help/root-contract/witness/generated/package
  surfaces, with npm-only non-runtime specification docs and cross-channel
  runtime behavior proof.

Shared stable-JSON/diagnostic hardening is owned by the supply-chain-quality
spec. Typed local-reference closure is owned by the existing agent-envelope
requirement. This workflow spec consumes those owners without duplicating them.

## Non-Claims

- Generated prompts are not authenticated and need not be obeyed or adequate.
- The built-in reviewed-change profile is optional guidance, not universal
  consuming-repository process policy or a custom workflow-graph engine.
- Static prompt bytes do not prove provider token use or model reasoning.
- Least dependency closure does not prove context truth, freshness, semantic
  sufficiency, or global minimality.
- A finite pilot does not prove universal repository fit.
- This spec does not select a persisted requirement-source codec.
- This spec does not approve merge, release, rollout, or production readiness.
