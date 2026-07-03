# Proofkit Backlog

This file is the canonical work ledger for completing the public
`research-engineering/agentic-proofkit` cutover. It tracks open work and blocked
claims. It is not a CLI manual, proof registry, or historical release log.

## Completion Criteria

Proofkit can be called complete as an organization-neutral reusable toolkit
only when these criteria are satisfied or explicitly retired by owner decision:

1. **Public source provenance is admitted.** A release is produced from this
   public source repository and records source, tag, package, registry, and
   release evidence.
2. **Public npm release is admitted.** A versioned release publishes or
   exact-byte-matches the root package, records post-publish npm identity,
   verifies root-only installation, proves JSON CLI ABI from the installed
   package, and documents rollback.
3. **Optional PyPI channel is admitted before it is claimed.** Python/uv wheels
   are candidate evidence until PyPI Trusted Publisher and post-publish PyPI
   registry identity are proven.
4. **Browser rendering is released.** Requirement source, proof, coverage, and
   spec-tree views are consumable through CLI rendering and loopback-only
   serving without requiring generated HTML in consumer repositories.
5. **Repository identity is organization-neutral.** Package metadata, README,
   agent entrypoint, docs, workflows, tests, and examples avoid organization-
   or consumer-specific authority.
6. **At least one consumer migration is proven from the public package.** A
   consuming repository replaces local or vendored Proofkit access with the
   public package, smokes the installed binary, records rollback, and keeps
   product semantics local.
7. **Second-consumer reuse is proven before broad reuse claims.** A second
   topology adopts one stable module in observe or warn mode with explicit
   caller-owned inputs.
8. **Agent guidance is usable.** Reports provide bounded envelopes that name
   what to inspect, who owns the decision, which proof route applies, what is
   omitted, and what escalation is required.
9. **Gradual adoption is usable for imperfect repositories.** A repository can
   scaffold starter records, define owner-reviewed requirements, bind proofs,
   run selective checks, and promote enforcement only after explicit owner
   approval.
10. **Self-hosting avoids circular proof.** Current-build Proofkit output may
    provide advisory self-consistency, but merge-critical proof must rely on
    native package gates, admitted CI producer policy, a prior release, or a
    minimal bootstrap verifier.
11. **Release-size changes are evidence-gated.** Platform-binary splitting,
    OCI, Homebrew, or Go module distribution is admitted only when measured
    consumer need outweighs added registry and adoption complexity.
12. **Generic authority invariants are upstream-owned.** Requirement-binding
    identity, test-inventory identity, report-shape admission, and other
    cross-repository mechanics live in Proofkit before consumers retire
    duplicate local checks.
13. **Hierarchical spec rendering is explicit-input and presentation-only.**
    Meta, module, and submodule spec chains can be rendered or exported from a
    caller-owned tree without implicit repository scanning or generated-output
    authority.

## Current Cutover State

| Status | ID | Scope | Completion condition |
|---|---|---|---|
| DONE | IMPORT-01 | Public project contract | Initial public README, license, contribution, security, and source-hygiene boundaries were admitted. |
| DONE | IMPORT-02 | Deterministic kernel primitives | Core Go admission, stable JSON, digest, report, path, release-platform, and package helper primitives were imported with tests. |
| DONE | IMPORT-03 | CLI command and release proof surface | CLI registry, command families, package/release tools, npm/PyPI wrapper surfaces, specs, proofkit JSON, and workflows were imported with local `npm run check`. Provider CI, protected-branch, registry, and release evidence remain separate open proof classes. |
| DONE | IMPORT-04 | Adoption and backlog owner surfaces | Public-ready adoption and backlog routing were added without stale private release facts or consumer-specific claims. |
| DONE | IMPORT-05 | Historical design and plan cleanup | Durable claims from pre-cutover design and implementation-plan work are represented by deterministic specs, proof bindings, tests, package-public docs, or open backlog rows. No source-repository design documents or implementation plans are retained as current authority. |
| DONE | IMPORT-06 | Remaining source-local code delta audit | Non-document source comparison found no old source file missing from the public source tree. Old source bytes remain candidate evidence only and are not imported over current hardening. |
| DONE | RELEASE-01 | Public source release | `v0.1.135` was published from this public repository through npm Trusted Publisher, post-publish npm registry identity was captured, root-only installed-package proof passed, and GitHub Release assets were published. PyPI publication and GitHub artifact attestations were skipped by explicit optional-channel policy and are not claimed. |
| OPEN | RELEASE-02 | Scoped npm package identity | `@research-engineering/agentic-proofkit@0.1.136` created the scoped public package namespace and Trusted Publisher settings without claiming workflow release provenance. Source is staged for `@research-engineering/agentic-proofkit@0.1.137` while preserving the `agentic-proofkit` CLI binary and Python package identities. Completion requires a `v0.1.137` release from public source through the scoped Trusted Publisher path, post-publish scoped npm registry identity, root-only installed-package JSON CLI ABI proof, and an explicit compatibility or deprecation disposition for the unscoped npm package. |
| DONE | SECURITY-01 | Provider security settings | Repository is public with collaborator-only PR creation, public issues, squash-only merges, branch protection on `main`, strict required CI, CodeQL, OSV source advisory scanning, Scorecard, Dependabot security updates, secret scanning, and push protection. Non-provider secret patterns and validity checks remain unavailable or disabled under the current provider plan and are not claimed. |
| DONE | CONSUMER-01 | Public-package consumer proof | A private first consumer repository consumed exact public npm `agentic-proofkit@0.1.134` through its repository-owned external-consumer gate. The proof installed the package into an isolated temporary consumer, matched the admitted tarball integrity and shasum, proved lockfile resolution was not workspace based, ran installed CLI `self-check`, `witness-plan`, and `release-authority`, proved rollback by removing the dependency from the temporary lockfile, and preserved consumer-owned native witness authority. |
| DONE | CONSUMER-02 | Second-consumer pilot | A private topology-distinct Python/FastAPI consumer module was run through explicit-input warn-mode `gradual-adoption-guidance` and `--agent-envelope` pilot records. Proofkit admitted the caller-owned route, reported one advisory candidate boundary, reported two missing proof-binding rule IDs as warnings, emitted route/bind/modernize/verify/promote agent actions, and kept enforcement blocked until consumer owners admit stable requirements and proof bindings. No generic Proofkit blocker was confirmed. |

## Release Evidence

`RELEASE-01` was admitted on 2026-07-03 from public repository
`research-engineering/agentic-proofkit` at commit
`2bbc36607734589f9e49191b4dc03eb37c65115b` and tag `v0.1.135`.

Provider run:

```text
https://github.com/research-engineering/agentic-proofkit/actions/runs/28677195127
```

The release workflow completed successfully. It ran the release candidate
package gate, publish readiness, npm Trusted Publisher publish, post-publish
registry capture, root-only installed-package JSON CLI ABI proof, final release
metadata generation, and GitHub Release asset publication. The npm registry now
reports `agentic-proofkit@0.1.135` with repository URL
`git+https://github.com/research-engineering/agentic-proofkit.git`,
tarball
`https://registry.npmjs.org/agentic-proofkit/-/agentic-proofkit-0.1.135.tgz`,
integrity
`sha512-GrLDm3P67JeWiEHCO5m/y1KiJ8hUSzZdQk7rM/Vgrqx3gphc21PQO27HwODFUDp4Gb62l1FpJ8v6b4i7dfY43A==`,
shasum `41722c3fa35dfa7cdea3d78e2aa940fb7d5cbcf3`, and license `MIT`.

The npm Trusted Publisher relationship for `agentic-proofkit` was moved from
the old source repository to GitHub Actions repository
`research-engineering/agentic-proofkit`, workflow file `release.yml`,
environment `npm-production`. PyPI publication was disabled for this release,
therefore PyPI registry identity is not claimed. GitHub artifact attestations
were skipped by current repository policy, therefore artifact attestation is
not claimed.

## Consumer Evidence

`CONSUMER-01` was admitted on 2026-07-03 from a private first consumer
repository checkout at `4cecdf8` using these consumer-owned gates:

```bash
bun run verify:proofkit-external-consumer
bun scripts/report-proofkit-external-consumer.selftest.ts
bun scripts/lib/proofkit-runtime.selftest.ts
bun scripts/verify-workspace-script-registry.selftest.ts
bun run verify:proofkit-pilot
bun run verify:proofkit-requirement-source
bun run verify:proofkit-requirement-coverage
```

The machine report for `bun scripts/report-proofkit-external-consumer.ts
--format json` emitted `reportKind: proofkit.registry-consumer`, `state:
passed`, `packageName: agentic-proofkit`, `packageVersion: 0.1.134`,
`registryUrl: https://registry.npmjs.org`, `tarballShasum:
6029a30b232c87f9aff659b4d8d5dbb4536a0d25`, `frozenLockUsesWorkspace:
false`, `releaseAuthorityReportKind: proofkit.release-authority`,
`releaseAuthorityState: passed`, and `rollbackLockContainsPackage: false`.

This evidence does not claim npm publication from this public source
repository, Trusted Publisher configuration, public-source release provenance,
provider-side security ingestion, PyPI publication, second-consumer reuse,
native consumer test execution by Proofkit, rollout readiness, production
readiness, or retirement of consumer-owned product semantics.

`CONSUMER-02` was admitted on 2026-07-03 from a private topology-distinct
consumer module using explicit caller-owned warn-mode adoption facts. The
Proofkit guidance report emitted `reportKind:
proofkit.gradual-adoption-guidance`, `state: passed`, `guidanceMode: warn`,
`candidateBoundaryCount: 1`, `proofBindingMissingCount: 2`, and warning rules
for `proofkit.gradual-adoption-guidance.missing-proof-bindings` and
`proofkit.gradual-adoption-guidance.candidate-boundaries`. The companion agent
envelope emitted `route`, `bind`, `modernize-boundary`, `verify`, and
`promote` actions, with candidate-boundary context refs and explicit
instructions to keep native witness execution outside Proofkit.

Gap classification:

- Generic Proofkit work: no confirmed blocker. The current CLI accepted
  explicit caller facts, preserved advisory candidate-boundary semantics, kept
  missing binding records as warnings in warn mode, and emitted bounded agent
  guidance without scanning repository state.
- Consumer-local adapter work: the consumer still needs owner-reviewed
  `requirements.v1.json` records, requirement-to-proof bindings, native witness
  command records, and a repository-local environment that can run its existing
  coverage-map and backend test commands. Native witness attempts were blocked
  by consumer-local dependency/bootstrap preconditions, not by Proofkit command
  semantics.

This evidence does not claim second-consumer enforcement, native witness
success, consumer rollout, production readiness, public package publication
from this source repository, provider-side registry evidence, or retirement of
consumer-owned coverage-map and test authority.

## Import Discipline

Old local repository content is not automatically authoritative. A transfer
batch is admissible only when:

```text
candidate file set
  and owner boundary
  and stale/private fact scan
  and lower-cost alternative review
  and proof gate
  and non-claims
```

Code from the old local repository is rejected when it would delete current
hardening, weaken package verification, remove non-disclosure tests, reduce
semantic-route proof, or replace current public-source wording with private
repository facts.

## Historical Import Discipline

Pre-cutover design documents and implementation plans are not retained in this
repository as current authority. Stable claims must move into deterministic
surfaces:

- `docs/specs/**/requirements.v1.json` for durable requirements;
- `proofkit/requirement-bindings.json` and `proofkit/witness-plan.json` for
  proof routes;
- source code and tests for executable behavior;
- package-public docs only when consumers need stable operational guidance;
- this backlog only for open, falsifiable work.

Temporary design, implementation-plan, PR, code, or test observations may be
caller-owned inputs to authoring commands, but they must not become tracked
repository authority unless rewritten into one of the deterministic surfaces
above.

Architecture documents, ADRs, or roadmap documents are not banned by type. They
are admitted only when they are the lowest-cost current authority for a real
architecture decision, migration sequence, release obligation, or adoption
contract. An admitted architecture document must state its owner, scope, proof
path, non-claims, and retirement or supersession condition; otherwise the claim
belongs in `requirements.v1.json`, machine contracts, executable tests,
package-public operational docs, or this backlog.

## Non-Goals

- Proofkit does not own product semantics for consuming repositories.
- Proofkit does not become a CI runner, repository scanner, policy owner, or
  proof freshness authority.
- Proofkit does not require generated HTML, generated Markdown, or generated
  lookup graphs to be committed by default.
- Proofkit does not require a rewrite in another language without measured
  evidence that the current Go CLI is the limiting factor.
