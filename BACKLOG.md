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
| BLOCKED | RELEASE-01 | Public source release | Public-source release candidate evidence passed from this repository. Final npm Trusted Publisher switch, version tag, publish, post-publish registry identity, optional PyPI evidence, GitHub Release assets, and rollback evidence are blocked on npm account recovery or maintainer authentication for `agentic-proofkit`. |
| DONE | SECURITY-01 | Provider security settings | Repository is public with collaborator-only PR creation, public issues, squash-only merges, branch protection on `main`, strict required CI, CodeQL, OSV source advisory scanning, Scorecard, Dependabot security updates, secret scanning, and push protection. Non-provider secret patterns and validity checks remain unavailable or disabled under the current provider plan and are not claimed. |
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
