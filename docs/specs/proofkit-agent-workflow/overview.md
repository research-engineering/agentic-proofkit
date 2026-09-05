# Proofkit Agent Workflow Spec

This spec owns Proofkit's generic support for planning one engineering-change
snapshot and for teaching a consuming repository to define executable native
evidence. It does not own consumer product meaning, repository policy,
witnesses, merge, release, rollout, or production-readiness decisions.

The public capability is deliberately small:

1. `change plan` admits explicit JSON and projects one next action for
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
4. `status --repo-root` classifies only a bounded normalized
   materialized-project observation, and `next --repo-root` projects one
   bounded action. Admitted in-bound records bind exact content digests;
   unread out-of-bound records bind only their invalid class. Neither command
   claims native execution or proof completion.
5. `integration source --tool <claude|codex>` emits one portable static
   bootstrap without reading repositories or writing files;
   `integration check --tool <claude|codex> --repo-root <path>` compares only
   the selected descriptor-owned file through confined read-only inspection.
   These are generation/check targets, not managed integration support.

The change planner and evidence-guidance cores are stateless pure projections.
Project status reads only an explicit repository root, the conventional routing
manifest, its declared children, and transaction control state through bounded
owner-admitted transport. No workflow command executes Git, native witnesses,
network, containers, or providers. No workflow command adds a setup facade,
hidden route policy, external prompt resource, persisted experiment state,
generic report interpreter, or second source codec. Agent-route brief and full
projections remain independently owned by the spec-proof-core package.

## Requirements

- `REQ-PROOFKIT-WORKFLOW-001`: one-time typed admission, pure deterministic
  projection, and derived-output authority boundary.
- `REQ-PROOFKIT-WORKFLOW-002`: named optional built-in profile, exact
  seven-stage order, prefix/checkpoint biconditional, and a disjoint terminal
  output.
- `REQ-PROOFKIT-WORKFLOW-003`: 28 active state rows, one terminal row,
  authority- and witness-gated executable envelope transitions, closed
  blockers and clarifications when those preconditions are absent, exact
  accepted-subject carry into each nonterminal successor, and an explicit
  terminal stop packet.
- `REQ-PROOFKIT-WORKFLOW-004`: typed subject/finding resolution, incoming
  subject identity on every noninitial stage, and internally consistent
  caller-declared digests.
- `REQ-PROOFKIT-WORKFLOW-005`: shared 256-byte stable-ID admission before work,
  global candidate-dependency resolution, one explicit nullable
  governing-authority reference, role-preserving bounded least dependency
  closure over explicit seeds, exact omission accounting, and output-byte
  limits.
- `REQ-PROOFKIT-WORKFLOW-006`: only existing launcher and presentation
  capabilities outside explicit input, with no ambient repository authority,
  setup facade, hidden policy, or ownership of agent-route projections.
- `REQ-PROOFKIT-WORKFLOW-007`: pure deterministic repository-neutral
  native-evidence guidance from one versioned typed table with five closed
  applicability classes, explicit absent-channel decisions, and finite
  nondisclosure corpora.
- `REQ-PROOFKIT-WORKFLOW-008`: display-safe caller admission, no-leak denial,
  exact retained-or-missing witness projection, bounded actionable and
  terminal text with required coordinates and exact rendered successor delta,
  and no styling of caller values.
- `REQ-PROOFKIT-WORKFLOW-009`: explicit text/color selection and confinement of
  ANSI to eligible terminal stdout.
- `REQ-PROOFKIT-WORKFLOW-010`: one production catalog owner for stage,
  checkpoint-schema, action-prerequisite, and successor semantics,
  independently authored semantic and literal-duplication oracles, and an
  AST-checked two-command carrier topology with no runtime experiment or
  external template residue.
- `REQ-PROOFKIT-WORKFLOW-011`: a finite factorized CLI relation closed across
  descriptor/dispatcher/family/help/root-contract/witness/generated/package
  surfaces, with npm-only non-runtime specification docs and cross-channel
  runtime behavior proof.
- `REQ-PROOFKIT-WORKFLOW-012`: one truthful project-state owner, exhaustive
  precedence, existing child and cross-record closure owners, and no promotion
  of source declarations or caller status into execution evidence.
- `REQ-PROOFKIT-WORKFLOW-013`: one application-write-free root-bound inspection
  lease, cooperative writer exclusion, descriptor-relative exact-path
  traversal, bounded content-cohort validation, fail-closed partial control
  observations, one bounded retry, and a portable non-disclosing
  normalized-observation identity.
  Filesystem-owned read metadata such as access time is outside that guarantee.
- `REQ-PROOFKIT-WORKFLOW-014`: one total state-to-action table, one bounded
  next action, explicit owner decisions, and no embedded route universe.
- `REQ-PROOFKIT-WORKFLOW-015`: status/next CLI channel and exit semantics,
  checkpointed pre-emission failure discipline, one bounded stdout write
  without claiming cancellation rollback or atomicity from an external sink,
  and a versioned breaking replacement
  of the flat change route by `change plan` across source and installed carriers.
- `REQ-PROOFKIT-WORKFLOW-016`: one private descriptor/template owner, portable
  approved-launcher guidance, 512-byte metadata and 4096-byte body limits, and
  identity over exactly consumed registered invocation contracts rather than
  package version or the entire command universe.
- `REQ-PROOFKIT-WORKFLOW-017`: pre-I/O invocation admission, a confined
  application-write-free two-observation check with an 8192-byte read bound per
  observation, distinct missing/current/stale/invalid states, non-disclosing
  operational failures, and independent cancellation/cleanup outcomes.
- `REQ-PROOFKIT-WORKFLOW-018`: exact source/check CLI flags, JSON root shapes,
  exit semantics, one source/check-only command family, and source, generated,
  and installed-carrier closure obligations. A binding is not an execution
  receipt; final frozen-tree and installed-carrier integration proof requires
  actual execution against the named source and artifacts.

Shared stable-JSON/diagnostic hardening is owned by the supply-chain-quality
spec. Typed local-reference closure is owned by the existing agent-envelope
requirement. This workflow spec consumes those owners without duplicating them.

## Thin Integration Boundary

The production owner is `internal/command/agentintegration`. The descriptor
alone selects `.agents/skills/agentic-proofkit/SKILL.md` for `codex` or
`.claude/skills/agentic-proofkit/SKILL.md` for `claude`. Source and check share
the same renderer. Common name/description frontmatter and static Markdown
delegate to the current CLI instead of embedding schemas or workflow policy.
The bootstrap persists logical routes, not machine-local executable paths;
an absent or ambiguous repository-approved installed launcher needs an owner
decision, never an implicit package manager, install, or network fallback.

The source contract's default JSON includes exact content and its digest;
`--format text` emits those file bytes. Check returns only expected generated
identity and a bounded freshness classification, never observed content, its
digest, or caller root paths. Exit 0 means current, exit 2 means a classified
missing/stale/invalid file, and exit 1 means an invocation or operation error.
Source returns 0 on success and 1 on error. Neither accepts `--output` or an
install option. Manual export guidance is owned by `ADOPTION.md`.

Phase5B managed installation, update, and safe removal remains explicitly open.
Host discovery, body loading, and approved-launcher invocation require separate
isolated native-host observations; direct CLI execution cannot prove skill use.

## Non-Claims

- Generated prompts are not authenticated and need not be obeyed or adequate.
- The built-in reviewed-change profile is optional guidance, not universal
  consuming-repository process policy or a custom workflow-graph engine.
- Static prompt bytes do not prove provider token use or model reasoning.
- Least dependency closure does not prove context truth, freshness, semantic
  sufficiency, or global minimality.
- A finite pilot does not prove universal repository fit.
- Bootstrap byte bounds are not token counts, and consumed registered-contract
  identity is not complete transitive semantic proof.
- Generated-byte freshness does not install, activate, authorize, or grant
  permissions. File removal does not revoke instructions already in host context.
- This spec does not select a persisted requirement-source codec.
- This spec does not approve merge, release, rollout, or production readiness.
