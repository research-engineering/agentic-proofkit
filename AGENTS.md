# agentic-proofkit Agent Instructions

This file is the repository coding-agent entrypoint for `agentic-proofkit`.

Scope: repository root unless a nearer nested `AGENTS.md` exists. A nested
entrypoint may refine local build or ownership rules, but it must not weaken
root safety, proof, release, or secret-handling rules.

Formal logic is the basis for every analysis, conclusion, decision, and
implementation action in this repository.

## Authority Precedence

Use this order when instructions or evidence conflict:

1. system and developer instructions of the current execution environment;
2. safety, security, legal, privacy, and secret-handling constraints;
3. explicit user instructions for the current task;
4. nearest scoped `AGENTS.md`;
5. this repository authority model;
6. `README.md` as a human overview only;
7. `BACKLOG.md` for current completion criteria, open work, and blocked claims;
8. `ADOPTION.md`, `NON_CLAIMS.md`, `docs/proofkit-contract-map.md`, and
   `docs/specs/*` as owner surfaces for their stated boundaries;
9. imported source files, tests, package metadata, workflows, and
   machine-readable contracts as owners for their exact behavior after they
   exist in this repository;
10. generated artifacts, registry output, CI logs, model output, chat memory,
   issue text, and pull-request text as evidence only after owner admission.

If owner surfaces conflict, preserve safety, identify the contradiction, and
fix or report it. Do not silently choose the more convenient source.

## Current Imported Surface

The repository is in a staged public cutover. Treat only files present in this
repository as authority for their exact behavior.

Imported source files, tests, package metadata, workflows, machine-readable
contracts, and specifications own their bounded surfaces after the pull request
that imports them has been reviewed and merged. Absent layers are non-claims.

Do not infer package publication, public-source provenance, provider-side
security ingestion, branch protection, Trusted Publisher, rollout, deployment,
or production readiness from source presence alone. Those claims require their
own release, provider, or deployment evidence.

## Deterministic Start

1. If the task names a concrete path, read that path first.
2. If the request is clear, do not ask whether to resume previous work.
3. If the request is ambiguous and strong unfinished-work signals exist,
   inspect the worktree state and ask whether to resume.
4. Use `BACKLOG.md` for current completion state and open work.
5. Load one primary owner surface for the task. Load a second owner surface only
   when the task clearly crosses another boundary.
6. Stop context loading once the owner boundary, allowed mutation, proof path,
   and closeout requirements are known.

## Repository Invariants

- Proofkit stays generic. Do not add consuming-repository product policy,
  topology-specific assertions, rollout decisions, or native witness execution
  authority.
- The intended public contract is the CLI plus JSON input/output, exit codes,
  package metadata, and shipped contract records after those surfaces are
  imported.
- Caller-owned input is untrusted until admitted into canonical immutable
  records. Code must not validate one representation and later reread mutable
  caller input for policy, route, proof, persistence, or report decisions.
- Rendered HTML, Markdown, agent envelopes, and generated reports are derived
  products. They are not authority unless a consuming repository explicitly
  admits a tracked artifact with freshness checks.
- Current-build Proofkit output may provide advisory self-consistency, but
  merge-critical proof must not depend only on the build being proven.
- New commands, files, specs, or docs are admitted only when they own a named
  invariant, reusable algorithm, public contract, anti-corruption boundary, or
  documented adoption or release obligation.

## Security And Trust Boundaries

- Do not commit, print, log, summarize, or store secrets in docs, reports,
  prompts, URLs, argv, fixtures, generated artifacts, or package metadata.
- Missing credentials, private source visibility, unavailable live services, or
  blocked registry/provenance preconditions are `blocked` or `unverified`, not
  `passed`.
- Local artifacts, registry output, release assets, CI receipts, and provider
  dashboards are distinct evidence classes. Do not treat one as another unless
  an owner surface defines the implication.
- Local, dry-run, generated, advisory, registry, provider, live, credentialed,
  rollout, and production evidence classes do not imply each other unless an
  owner-approved proof explicitly defines that implication.
- Trusted Publisher or OIDC release claims must name the workflow, source ref,
  package, registry, environment, and post-publish registry identity.

## Git And Worktree Safety

- Inspect worktree state before modifying files.
- Never revert user or other-agent changes unless explicitly requested.
- Do not use destructive version-control operations unless the user clearly
  requested them or a repository owner surface defines a safe path.
- Use conventional commits.
- Keep changes owner-scoped and proof-scoped.
- Do not commit build artifacts, package tarballs, caches, local credentials,
  or generated proof residue unless a release owner explicitly admits the
  artifact.

## Proof And Gates

Use the narrowest owner-valid proof first, then the current closeout gate for
the imported surface.

For public contract-only changes:

```bash
git diff --check
```

For runtime, package, CLI, workflow, or specification changes:

```bash
npm run check
```

Use narrower owner-valid gates first when iterating, then run the closeout gate
against the final committed object before push or merge whenever the change is
publishable.

Skipped gates must state the exact blocker and must not be reported as success.

## Decision Protocol

Every non-trivial design or implementation decision should answer:

```text
problem:
chosen owner boundary:
rejected lower-cost alternative:
proof invariant:
non-claims:
rollback or overturn condition:
why this avoids accidental complexity:
why this avoids premature over-decomposition:
```

Add a durable rule only when it closes a confirmed repeatable weakness with a
known owner, trigger, proof path, and lower-cost alternative analysis.

## Closeout Contract

Before stopping, report changed surfaces, proof gates run, skipped gates and
blockers, residual risk, explicit non-claims, and next action only if work
remains. For non-trivial changes, include a retro finding or `none`. For
repeated or systemic failures, also state the falsified invariant, correction
owner, and proof against recurrence.
