# Proofkit Receipt Authority Spec

This spec owns Proofkit's reusable receipt authority primitives: proof receipt
shape admission, receipt producer policy linkage, producer-policy self-proof
guards, and spec-proof bundle linkage between requirements, witness plans,
producer admission, and receipts.

It is intentionally infrastructure-only. Consumers authenticate producers,
define trust roots, execute native witnesses, compute freshness, match current
obligations, and decide merge, release, rollout, and production policy.

## Requirements

- `REQ-PROOFKIT-RECEIPT-001`: proof receipt admission validates caller-provided
  receipt shape, digests, timestamps, selectors, evidence refs, artifact refs,
  status, and provenance fields without authenticating producers or computing
  freshness.
- `REQ-PROOFKIT-RECEIPT-002`: receipt producer admission validates
  caller-owned producer policy and receipt metadata linkage without proving that
  the producer actually created the receipt.
- `REQ-PROOFKIT-RECEIPT-003`: producer-policy self-proof detects when
  merge-obligation receipts depend on trust tuples newly admitted by the same
  policy change without approving or rejecting the policy change itself.
- `REQ-PROOFKIT-RECEIPT-004`: spec-proof bundle admission validates linkage
  across requirement bindings, witness plans, producer admission, and receipt
  admission without executing native witnesses or approving merge.

## Non-Claims

- This spec does not authenticate CI, local runners, or receipt producers.
- This spec does not compute receipt freshness or current-obligation
  satisfaction.
- This spec does not execute commands or verify native command pass evidence.
- This spec does not approve merge, release, registry publication, rollout, or
  production readiness.
