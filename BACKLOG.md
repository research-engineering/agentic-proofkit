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
| NEXT | IMPORT-05 | Design documents | Import or rewrite design documents in owner-scoped groups only after each claim is checked against current code and package shipping rules. |
| OPEN | IMPORT-06 | Remaining source-local code delta audit | Treat remaining source-local code diff as candidate evidence only. Import no code unless the target branch lacks the invariant and the delta does not remove current hardening. |
| OPEN | RELEASE-01 | Public source release | Publish a new version from this public repository and record npm, optional PyPI, GitHub Release, SBOM, and rollback evidence. |
| OPEN | SECURITY-01 | Provider security settings | Verify CodeQL, dependency review or equivalent advisory scanning, secret scanning, push protection, branch protection, and issue/PR policy in provider settings. |
| OPEN | CONSUMER-01 | Public-package consumer proof | Run at least one consumer through exact package adoption, installed CLI smoke, rollback proof, and native-witness delegation. |
| OPEN | CONSUMER-02 | Second-consumer pilot | Run a small observe or warn pilot in a topology-distinct repository and classify every gap as generic Proofkit work or consumer-local adapter work. |

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

## Open Design-Import Questions

Before importing each design document group, answer:

1. Does the document own current architecture, future work, or historical
   context?
2. Is every `must`, `shall`, `guarantee`, readiness, release, or security claim
   still true on current `main`?
3. Does the document name a stable owner surface and proof path?
4. Would the document become package authority if shipped? If yes, is it
   public-ready and covered by package verification?
5. Can the same useful content be expressed in `ADOPTION.md`,
   `docs/proofkit-contract-map.md`, a spec requirement, or the backlog with
   less token load?

Current import rule:

- `docs/document-lifecycle-boundary-design.md` is admitted as the first
  source-repository design surface because it defines the lifecycle boundary
  needed to review every later design document.
- `docs/requirement-source-admission-design.md` and
  `docs/spec-overview-claim-boundary-design.md` are admitted source-repository
  design surfaces for the requirement source authority boundary.
- `docs/requirement-source-transition-design.md` is admitted as the source-
  repository design surface for requirement lifecycle transition admission.
- Implementation plans remain excluded from package-public docs and should be
  deleted, rewritten into durable design notes, or left unimported after their
  useful invariants have moved into code, tests, specs, or this backlog.
- Source-repository design docs are not package authority unless package files,
  package verification, and release evidence explicitly admit them.

## Non-Goals

- Proofkit does not own product semantics for consuming repositories.
- Proofkit does not become a CI runner, repository scanner, policy owner, or
  proof freshness authority.
- Proofkit does not require generated HTML, generated Markdown, or generated
  lookup graphs to be committed by default.
- Proofkit does not require a rewrite in another language without measured
  evidence that the current Go CLI is the limiting factor.
