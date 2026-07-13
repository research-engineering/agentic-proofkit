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
  for package, wheel, binary, and Go module inventory without claiming
  vulnerability absence or license approval.
- `REQ-PROOFKIT-QUALITY-003`: pure parser and canonicalization boundaries have
  fuzz/property tests that prove no-panic and round-trip stability without
  fuzzing side-effecting CLI or filesystem flows.
- `REQ-PROOFKIT-QUALITY-004`: public CLI ABI has a small golden corpus and
  canonical ABI hash covering command topology, exit code, stdout/stderr
  channel discipline, JSON parseability, stable public diagnostics, explicit
  output schema evolution for breaking JSON field changes, and
  descriptor/contract/help parity without making private descriptors public API.
- `REQ-PROOFKIT-QUALITY-005`: CodeQL workflow source is admitted as an
  independent semantic security analysis signal for Go source without replacing
  native Go static gates.
- `REQ-PROOFKIT-QUALITY-006`: OSV workflow source is admitted as an advisory
  multi-ecosystem dependency signal without replacing `govulncheck`
  reachable-code evidence.
- `REQ-PROOFKIT-QUALITY-007`: Scorecard workflow source is admitted as an
  advisory repository hygiene signal without claiming branch protection or
  provider settings that the repository cannot prove from source.
- `REQ-PROOFKIT-QUALITY-008`: GitHub Actions workflow syntax and expression
  semantics are checked by actionlint in the local package gate.
- `REQ-PROOFKIT-QUALITY-009`: performance-sensitive parser and serializer
  paths expose benchmark entrypoints without making wall-clock budgets a
  required PR gate before stable baselines exist.
- `REQ-PROOFKIT-QUALITY-010`: coverage metrics report requirement, binding,
  witness, CLI inventory linkage, and descriptor-owned command proof-route
  candidates from admitted test-evidence-inventory rows. The gate fails closed
  on linkage dead zones, failed inventory admission, missing candidates,
  unknown command refs, contract-only commands, or route-only commands. Static
  route metadata and source syntax never become semantic falsifier evidence.
- `REQ-PROOFKIT-QUALITY-011`: CI separates the OS-independent full
  source/package gate from macOS platform smoke, executes the complete Go
  package set through its owner command, uses explicit hosted runner labels
  instead of floating latest labels, and exposes one fail-closed aggregate gate
  that requires every required leaf check to finish with success.
- `REQ-PROOFKIT-QUALITY-012`: release and adoption channel identifiers use one
  canonical authority vocabulary that separates durable authority channels from
  display labels, publisher environments, statuses, and candidate evidence.
- `REQ-PROOFKIT-QUALITY-013`: self-hosting workflow package-gate evidence is
  checked by a typed workflow oracle instead of text search, proving the
  package gate is reachable, exact, advisory, success-gated for always-running
  downstream jobs and required evidence-publication steps, and ordered before
  evidence publication.
- `REQ-PROOFKIT-QUALITY-014`: release authority consumers compare downstream
  policy against the admitted typed release-authority projection and admitted
  report digest instead of rereading caller-owned raw `releaseAuthorityInput`
  fields after validation.
- `REQ-PROOFKIT-QUALITY-015`: the package gate includes an admitted release
  closeout completion-criteria report so unit tests alone cannot satisfy
  release closeout.
- `REQ-PROOFKIT-QUALITY-016`: release platform targets use one private owner
  that projects platform suffixes, Go build targets, npm OS/CPU metadata,
  package tar entries, Python wheel tags, PyPI candidate completeness,
  self-hosting native binary selection, and SBOM binary subjects without
  becoming public API.
- `REQ-PROOFKIT-QUALITY-017`: report-visible secret-shaped JSON traversal
  uses one private kernel owner for deterministic paths and finding kinds while
  command packages only map findings to their local report policy.
- `REQ-PROOFKIT-QUALITY-018`: release metadata retains a Trusted Publisher
  identity tuple with the exact version-tag workflow ref for workflow-published
  npm and PyPI channels and release closeout rejects publication claims without
  that tuple.
- `REQ-PROOFKIT-QUALITY-019`: installed package smoke proof verifies one
  successful JSON report command, one failed-report command, and the current
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
  artifacts, and machine-admitted per-project rendered engine evidence without
  runtime dependencies or a production bundler.
- `REQ-PROOFKIT-QUALITY-023`: Python wheels independently bind advertised
  platform compatibility to decoded executable bytes and carry Core Metadata
  2.4 plus an exact, RECORD-closed repository license payload.
- `REQ-PROOFKIT-QUALITY-024`: a version-bound machine record declares the
  reviewed public-contract change set and owns release-note content, while one
  retained-evidence owner builds and verifies checksums against exact
  downloadable artifact-relative paths without inferring change completeness
  from the source diff.

## Non-Claims

- This spec does not claim public-source provenance until a public-source tag
  release records admitted attestation evidence.
- This spec does not claim absence of vulnerabilities, license approval,
  branch-protection enforcement, consumer adoption, merge approval, release
  approval, rollout approval, or production readiness.
- This spec does not make advisory security scans substitute for native tests,
  parser fuzz/property tests, CLI ABI tests, release manifest generation, or
  registry identity evidence.
