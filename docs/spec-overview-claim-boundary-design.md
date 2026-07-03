# Spec Overview Claim Boundary Design

Status: implemented source-repository design.

Owner: `proofkit`.

## Problem

Human spec overviews are useful for context, examples, diagrams, and rationale,
but durable requirement meaning must live in structured `REQ-*` records. If an
overview sentence says a system `must`, `shall`, `guarantees`, or `always` does
something without citing a `REQ-*`, the overview becomes a second source of
truth.

## Decision

`spec-overview-claims` emits a deterministic report over caller-provided
overview claim extraction facts.

The primitive validates:

- `overviewPath` equals `specPackagePath/overview.md`;
- `requirementsPath` equals `specPackagePath/requirements.v1.json`;
- every durable overview claim cites at least one known `REQ-*`;
- every cited `REQ-*` is declared by the caller-provided requirement id set;
- non-durable claims do not carry requirement citations;
- extraction refs, line digests, detected markers, rationale, and non-claims
  are explicit and deterministic.

## Authority Boundary

Proofkit validates extracted claim facts. It does not read Markdown, detect
claims from source text, prove extractor completeness, decide whether a cited
`REQ-*` semantically supports the sentence, validate requirement source records,
or approve merge.

Design documents in this repository are source-repository reasoning surfaces.
They are not shipped package authority unless `package.json`, package
verification, and release evidence explicitly admit them as package-public
surfaces.

## Rejected Alternatives

| Alternative | Rejected because |
|---|---|
| Fold this into requirement-source admission. | Structured requirement records and overview prose extraction have different authority boundaries. |
| Parse Markdown inside Proofkit. | Consumer repositories own extraction witnesses, ignored-region policy, and Markdown provenance. |
| Allow overview durable claims without citations when wording is obvious. | That reintroduces duplicate durable truth and breaks fail-closed traceability. |
| Let non-durable lines cite `REQ-*`. | It makes examples and rationale look normative and blurs the citation contract. |

## Follow-Up

Consumer repositories should pair this primitive with a native extractor witness
that turns `overview.md` into claim records, including ignored regions and line
digests. Proofkit validates the resulting facts only.
