# Document Lifecycle Boundary Design

Status: implemented source-repository design.

Owner: `proofkit`.

## Problem

Design documents and implementation plans are useful while a pull request is
open, but they stop being durable behavior authority after merge. Current
repository truth must move to requirement records, specifications, proof
bindings, routers, work ledgers, package-public docs, or generated lookup
surfaces with explicit freshness boundaries.

Without a lifecycle boundary, historical prose can keep routing agents as if it
were current behavior, proof, readiness, or open-work authority.

## Decision

`document-lifecycle-boundary` emits a deterministic report over
caller-provided document lifecycle records.

The primitive validates lifecycle authority classification:

- active PR-local design and implementation-plan documents stay temporary
  reasoning inputs;
- merged design and implementation-plan documents are historical evidence only;
- retained merged implementation plans are historical evidence only and cannot
  keep active routing or owner authority;
- merged temporary documents are not routed as current authority;
- archived documents do not keep active authority or current routing roles;
- generated views stay lookup-only and declare source and freshness refs;
- rendered views stay presentation-only and declare source and freshness refs;
- generated views are routed only as lookup projections, and rendered views are
  routed only as presentation views, not owner surfaces;
- current durable documents declare freshness checks;
- primary routers use navigation authority;
- work ledgers use open-work authority;
- every document declares owner, mutation triggers, forbidden payloads, and
  non-claims.

## Authority Boundary

Proofkit validates caller-provided lifecycle metadata and emits deterministic
diagnostics. It does not read Markdown, parse document semantics, infer routes,
prove generated freshness, archive files, delete files, approve merge, or
decide product meaning.

Deletion approval and evidence-preservation judgment remain repository-owner
decisions outside this primitive. The report can say whether a retained
temporary document is still routed as current authority; it cannot decide that a
file should be deleted.

Design documents in this repository are source-repository reasoning surfaces.
They are not shipped package authority unless `package.json`, package
verification, and release evidence explicitly admit them as package-public
surfaces.

## Rejected Alternatives

| Alternative | Rejected because |
|---|---|
| Parse Markdown directly in Proofkit. | Document meaning, prose style, and semantic extraction remain repository-owned. |
| Fold lifecycle checks into requirement-source admission. | Requirement records and documentation topology have different authority boundaries. |
| Treat merged plans as current owner surfaces if they contain useful detail. | That preserves stale PR-local reasoning as durable truth. |
| Track rendered views as canonical source. | Rendered views are presentation surfaces only; source records own durable meaning. |

## Follow-Up

Consumer repositories can feed this report into selective gates or adoption
checklists. If they need semantic Markdown linting, they should provide
caller-owned facts to this primitive or implement a separate native witness.
