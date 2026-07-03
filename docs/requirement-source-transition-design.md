# Requirement Source Transition Design

Status: implemented source-repository design.

Owner: `proofkit`.

## Problem

Requirement source admission validates one `requirements.v1.json` snapshot. It
cannot prove that a pull request changed requirement lifecycle records
monotonically because it does not receive the previous source package.

Formal gap:

```text
Durable REQ-* identity must survive ordinary source edits.
Single-snapshot admission cannot observe from-to lifecycle changes.
Therefore lifecycle transition admission needs caller-provided previous and next
source records.
```

## Decision

`requirement-source-transition` emits a deterministic report over explicit
previous and next requirement source snapshots.

The primitive validates:

- both snapshots pass requirement source admission;
- both snapshots describe the same `sourceId`, `specPackagePath`,
  `overviewPath`, and `requirementsPath`;
- durable previous `REQ-*` records remain present in the next source before
  deletion;
- new requirements start as `active`;
- terminal `removed` and `superseded` states do not change later;
- terminal `superseded` replacement sets do not expand or shrink later;
- deprecation, removal, supersession, and reactivation transitions carry a
  lifecycle evidence ref that was not already present in the previous source;
- superseded requirements replace only to requirements that are active in the
  next admitted source;
- previous lifecycle evidence and replacement refs are not silently dropped.

## Authority Boundary

Proofkit owns reusable transition grammar and deterministic diagnostics only.

Consumer repositories own:

- finding the previous and next source records;
- requirement sentence meaning;
- replacement semantic equivalence;
- proof-binding adequacy;
- witness execution and receipt freshness;
- merge, release, rollout, and deletion approval.

## Rejected Alternatives

| Alternative | Rejected because |
|---|---|
| Add previous-state fields to every requirement source record. | It would mix durable source truth with PR-local transition evidence and make stable specs noisier. |
| Infer the previous source by scanning git history. | Proofkit must stay repository-neutral and must not own VCS access or freshness. |
| Fold transition checks into proof bindings. | Proof bindings own verification routes, not source lifecycle identity. |

## Non-Claims

The report does not discover diffs, prove replacement equivalence, execute
native witnesses, compute freshness, approve record deletion, or decide merge.
