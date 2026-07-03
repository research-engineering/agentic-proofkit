# Requirement Source Admission Design

Status: implemented source-repository design.

Owner: `proofkit`.

## Problem

Spec-first proof architecture needs a machine-admissible source record before
requirement-to-proof bindings can be trusted. Proof binding validation accepts
requirement rows as routing input, but it does not validate the canonical
`requirements.v1.json` source package lifecycle.

Formal gap:

```text
Structured requirement records own durable machine identity.
Proof binding records own verification routes.
Therefore requirement source admission must succeed before downstream routes
can rely on stable REQ-* identity.
```

## Decision

`requirement-source-admission` emits a deterministic report over
caller-provided requirement source records.

The primitive validates:

- exact `docs/specs/<capability>/overview.md` and
  `docs/specs/<capability>/requirements.v1.json` package shape;
- stable sorted `REQ-*` records;
- exact requirement source fields;
- claim level, risk class, owner, invariant text, non-claim refs, and
  non-claims;
- lifecycle state, replacement traceability, and removal evidence;
- non-active lifecycle evidence and active replacement targets;
- deferral policy for deferred requirements;
- non-empty `proofBindingRefs` for active blocking requirements;
- update policy for impact declaration and proof-binding review.

## Authority Boundary

Proofkit owns reusable admission grammar and deterministic diagnostics only.

Consumer repositories own:

- requirement sentence meaning;
- whether a requirement should exist;
- proof-binding adequacy;
- native witness behavior;
- producer admission and receipt freshness;
- merge, release, rollout, and deferral approval.

## Rejected Alternatives

| Alternative | Rejected because |
|---|---|
| Extend `requirement-bindings` to validate source lifecycle. | It would merge source authority and proof-route authority, making the first layer harder to review and reuse. |
| Parse Markdown overview files. | Proofkit must not read implicit repository state or infer durable claims from prose. Caller-owned extraction facts must be supplied to separate overview-claim admission. |
| Make source admission execute proof bindings. | Execution and freshness belong to native witnesses, receipts, and consumer CI policy. |

## Non-Claims

The report does not prove that the overview file has no uncited durable claims,
that proof bindings are adequate, that tests pass, or that merge is allowed.
