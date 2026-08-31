# Proofkit Supply-Chain And Quality Spec

This spec owns Proofkit's reusable supply-chain, release-provenance, CLI
contract, property-test, performance-evidence, security-signal, and coverage
metrics requirements.

It is intentionally evidence-focused. Native tests, release workflows, advisory
security workflows, and generated evidence files are distinct proof classes.
No single green check proves release readiness, public-source provenance,
vulnerability absence, or consumer rollout safety by itself.

## Requirements

- `REQ-PROOFKIT-QUALITY-001`: release artifacts carry deterministic digest
  inventory and optional GitHub artifact attestations without claiming
  public-source provenance before a public-source tag release exists.
- `REQ-PROOFKIT-QUALITY-002`: release evidence includes a deterministic SBOM
  whose runtime edges and digest come from one immutable byte snapshot of the
  exact owning binary through an identity-checked pinned handle with a final
  same-handle content check; source/tool module inventory is excluded and
  package or wheel representations invent no runtime edges.
- `REQ-PROOFKIT-QUALITY-003`: pure parser and canonicalization boundaries have
  fuzz/property tests that prove no-panic and round-trip stability without
  fuzzing side-effecting CLI or filesystem flows.
- `REQ-PROOFKIT-QUALITY-004`: public CLI ABI has a small golden corpus and
  canonical ABI hash covering command topology, exit code, stdout/stderr
  channel discipline, JSON parseability, stable public diagnostics, complete
  versioned root-shape input/output variants, exact source-checkout selectors,
  exact native source sets and requirement scenarios for root-distinct output
  witnesses, generated help and preset projections, explicit root schema
  evolution, and descriptor/contract/help parity without making private
  descriptors public API. The admitted adoption-envelope machine condition
  model uses complete
  canonical flag conjunctions, proves finite valid-option closure against
  native admission, binds exercised argv to one exact condition and variant,
  and rejects repeated mode or pilot selectors plus an empty pilot value that
  would normalize to absence. Any later condition-model owner requires its own
  admitted native-closure witness. The separate pilot-admission route declares
  its contract-envelope stack-diverse alias and rejects repeated or mixed
  `--pilot` and `--stack-diverse` selectors instead of applying last-write-wins
  routing. Nested fields, leaf types, cardinality,
  nullability, and cross-field semantics remain native-command concerns rather
  than machine-contract claims.
- `REQ-PROOFKIT-QUALITY-005`: CodeQL workflow source is admitted as an
  independent semantic security analysis signal for Go source; advisory
  analysis remains read-only, provider publication is isolated and disabled on
  pull requests, and native Go static gates remain required.
- `REQ-PROOFKIT-QUALITY-006`: OSV workflow source is admitted as an advisory
  multi-ecosystem dependency signal; advisory analysis remains read-only,
  provider publication is isolated and disabled on pull requests, and
  `govulncheck` reachable-code evidence remains required.
- `REQ-PROOFKIT-QUALITY-007`: Scorecard workflow source is admitted as an
  advisory repository hygiene signal; advisory analysis remains read-only,
  public publication authority is isolated with exact output inputs, and
  source does not claim branch protection or unobserved provider settings.
- `REQ-PROOFKIT-QUALITY-008`: GitHub Actions workflow syntax and expression
  semantics are checked by actionlint in the local package gate.
- `REQ-PROOFKIT-QUALITY-009`: performance-sensitive parser and serializer
  paths expose benchmark entrypoints without making wall-clock budgets a
  required PR gate before stable baselines exist.
- `REQ-PROOFKIT-QUALITY-010`: coverage metrics keep static proof-route
  candidates separate from an execution-backed command-oracle ledger. The
  ledger runs exact selected Go tests through package-scoped argv vectors from
  one exact-file materialized source snapshot, joins reserved lifecycle
  attributes to every candidate identity, terminates bounded subprocesses on
  cancellation or output overflow, confines atomic artifact publication and
  invalidation to non-symlink repository paths, and fails closed on incomplete
  command coverage or event, source, selection, producer-reachability, and
  identity drift. A versioned counterfeit corpus owns checked-in expected
  decisions for every required policy axis, evidence class, record coordinate,
  and substitution axis; its mutations execute the production admission and
  lifecycle owners rather than a generated expectation copy. Passing selected
  tests does not prove assertion-branch execution, mutation adequacy, or
  exhaustive command semantics.
- `REQ-PROOFKIT-QUALITY-011`: CI separates the OS-independent full
  source/package gate from macOS platform smoke, executes the complete Go
  package set through its owner command, uses explicit hosted runner labels
  instead of floating latest labels, and exposes one fail-closed aggregate gate
  whose exact expression and script reject neutralization and require every
  required leaf check to finish with success, while the aggregate job omits
  job defaults and `continue-on-error` entirely. Exact workflow-level bash
  defaults plus a closed inventory require exact provider-check names and
  scalar runners, bind the macOS job's presence-aware exact ordered step
  inventory and exact local setup-action bytes to the fail-closed
  package-script owner command, require every required leaf job and step to
  omit conditions except for exact named owner conditions, and reject
  dynamically false or explicit-null conditions, dual `run`/`uses` keys,
  non-string runner labels, nested or top-level semantic shadow steps,
  reusable-job substitution, inherited or local environment entries, shell,
  working-directory, and `continue-on-error` overrides.
- `REQ-PROOFKIT-QUALITY-012`: release and adoption channel identifiers use one
  canonical authority vocabulary that separates durable authority channels from
  display labels, publisher environments, statuses, and candidate evidence.
- `REQ-PROOFKIT-QUALITY-013`: self-hosting workflow package-gate evidence is
  checked by a typed workflow oracle instead of text search, proving the
  package gate is reachable, exact, advisory, and guarded only by absent or
  exact owner-reviewed conditions for every trust-significant job and step
  across the closed required CI and release inventories; dynamically false and
  neutralized expressions are rejected alongside unsafe workflow run defaults,
  unexpected workflow or step environment entries, gate-job defaults or
  environment entries, and shell, working-directory, or
  `continue-on-error` override on any step in the gate job; the gate remains
  ordered before evidence publication.
- `REQ-PROOFKIT-QUALITY-014`: release authority consumers compare downstream
  policy against the admitted typed release-authority projection and admitted
  report digest instead of rereading caller-owned raw `releaseAuthorityInput`
  fields after validation.
- `REQ-PROOFKIT-QUALITY-015`: the package gate includes an admitted release
  closeout completion-criteria report so unit tests alone cannot satisfy
  release closeout. Coverage re-admission rejects candidate-only v1, requires
  overflow-safe exact producer relations plus the complete command inventory,
  and binds coverage v2 to the current command-oracle diagnostic through the
  ledger owner's one-read canonical admission, current-owner revalidation, and
  record, candidate-set, corpus, revision, and source-snapshot digests.
- `REQ-PROOFKIT-QUALITY-016`: release platform targets use one private owner
  that projects platform suffixes, Go build targets, npm OS/CPU metadata,
  package tar entries, Python wheel tags, PyPI candidate completeness,
  self-hosting native binary selection, SBOM binary subjects, and the exact
  marker-bounded README platform matrix without becoming public API.
- `REQ-PROOFKIT-QUALITY-017`: report-visible secret-shaped JSON traversal
  uses one private kernel owner for deterministic paths and finding kinds while
  command packages only map findings to their local report policy.
- `REQ-PROOFKIT-QUALITY-018`: release metadata retains a Trusted Publisher
  identity tuple with the exact version-tag workflow ref for workflow-published
  npm and PyPI channels and release closeout rejects publication claims without
  that tuple.
- `REQ-PROOFKIT-QUALITY-019`: installed package smoke proof verifies one
  continuous offline route through every displayed family and leaf-help
  transition, binds each installed invocation to its ordered exact bare Usage
  command token, requires every exact generated preset command to retain the
  offline npm prefix, re-executes one emitted continuation, reaches the first
  valid README input, executes one successful JSON report command and one
  failed-report command, applies bounded expansion-free literal parsing to
  emitted and README argv, and verifies the current
  `json-report-cli-adapter-source` generated source artifact from the
  package-managed binary, including report identity, state, exit code, stdout,
  stderr discipline, generated-source hash, owner-source parity, and exact
  explicit-input counts despite an unlisted poison file in the consumer working
  directory.
- `REQ-PROOFKIT-QUALITY-020`: package artifact execution starts from admitted
  candidate-owned output roots, rejects ambient provider or unowned release
  state before mutation, stays confined to the repository across symlinks,
  binds non-empty generated content to stable source and execution-context
  snapshots, and emits a schema-versioned execution record.
- `REQ-PROOFKIT-QUALITY-021`: CLI contract v2 owns one leading pretty or
  compact JSON layout option through a descriptor-aware token-role
  preclassification at process output boundaries while canonical identity
  serialization remains unchanged.
- `REQ-PROOFKIT-QUALITY-022`: the requirement workspace uses an explicit
  embedded asset set, strict authored-JavaScript type checking, exact secured
  routes, bounded server cleanup, repository-confined non-symlink proof
  artifacts, and machine-admitted per-project rendered engine evidence for its
  stable-state accessibility matrix, including independently held bootstrap,
  specifications, diff, and graph loading states, target size, 320-pixel
  reflow, labelled internal overflow, and light/dark rendered contrast without
  runtime dependencies or a production bundler; one direct audit initializes
  pinned axe code through the browser-context script channel, admits only the
  main frame and exact engine identity, preserves same-origin and Playwright
  branding, and runs default rules plus explicitly enabled target size, while
  failed attempts retain attempt-scoped action, DOM, network, and source traces
  without continuous screenshot capture plus a bounded best-effort failure
  screenshot, without creating passed proof.
- `REQ-PROOFKIT-QUALITY-023`: npm platform binaries and Python wheels
  independently bind to the same release binary for every target; a separate
  bounded decoder also compares the final tar and wheel members directly,
  without a mutable intermediate; package-set wheel and embedded-binary digest
  claims, including npm SHA-1/SRI, must equal bytes decoded from one immutable
  snapshot and release closeout recomputes them through repository-confined,
  bounded, identity-checked non-symlink handles; wheels bind advertised platform
  compatibility to decoded executable bytes, reject version, identity,
  presence, and digest drift, and carry Core Metadata 2.4 plus an exact,
  RECORD-closed repository license payload.
- `REQ-PROOFKIT-QUALITY-024`: a closed version-bound machine record binds the
  exact previous/current SemVer pair and compatible/breaking class, declares the
  exact complete current breaking, addition, and migration inventories
  including channel-specific generated continuation bytes, rejects missing,
  substituted, reordered, or surplus entries, and owns one independently
  authored byte-exact complete current release-note projection. Candidate
  preflight binds npm latest to `previousVersion` for an unpublished candidate
  or to `version` only after exact existing-byte-match proof. One retained-
  evidence owner builds and verifies checksums against exact
  downloadable artifact-relative paths without inferring change completeness
  from the source diff.
- `REQ-PROOFKIT-QUALITY-025`: exact workflow inventory, closed raw-YAML keys
  before typed decoding, exact release deployment environments, pinned action
  commit identities, admitted status expressions, the required aggregate shell
  program, and read-only treatment of an existing release are source-oracle
  invariants.
- `REQ-PROOFKIT-QUALITY-026`: every public or retained-evidence stable JSON
  implementation accepts only the repository-pinned Unicode scalar set and matches one
  preimplementation byte corpus for the pinned control, format, and separator
  table without changing decoded values.
- `REQ-PROOFKIT-QUALITY-027`: report-visible diagnostics and structural text
  apply the same scalar, Unicode-whitespace, control/format, and split-secret
  taxonomy, replace rejected caller values as a whole without echoing any
	  fragment, bound diagnostic output, and own dynamic Go/JavaScript error
	  projection plus failure-only bounded child-process diagnostics for repository
	  tools. On supported Unix hosts, an installed-carrier success additionally
	  requires confirmed process-group absence after the parent is reaped; cleanup
	  timeout is an explicit failure rather than a successful terminal result.

## Non-Claims

- This spec does not claim public-source provenance until a public-source tag
  release records admitted attestation evidence.
- This spec does not claim absence of vulnerabilities, license approval,
  branch-protection enforcement, consumer adoption, merge approval, release
  approval, rollout approval, or production readiness.
- This spec does not make advisory security scans substitute for native tests,
  parser fuzz/property tests, CLI ABI tests, release manifest generation, or
  registry identity evidence.
