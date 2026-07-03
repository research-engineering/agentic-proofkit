# agentic-proofkit

Reusable CLI and JSON proof infrastructure for spec-to-proof workflows in
software repositories.

`agentic-proofkit` helps repositories validate structured requirements, bind
requirements to proof routes, plan selective checks, admit receipt-shaped
evidence, render human views, and give coding agents bounded next-action
packets without copying verifier logic between projects.

## Current Repository State

| Surface | State |
|---|---|
| Source visibility | Public |
| Current layer | Public source with admitted unscoped npm release evidence; scoped npm identity has a bootstrap namespace release and is staged for Trusted Publisher release evidence |
| Runtime implementation | Go CLI with npm and Python wrapper packaging |
| Package release | `agentic-proofkit@0.1.135` is admitted; `@research-engineering/agentic-proofkit@0.1.136` is bootstrap-published; `@research-engineering/agentic-proofkit@0.1.137` proved scoped Trusted Publisher publication but not full release closeout; `@research-engineering/agentic-proofkit@0.1.138` is pending release evidence |
| Public-source provenance | Admitted for `v0.1.135`; scoped package Trusted Publisher provenance is pending a reviewed scoped release |
| License | MIT |

## Project Boundary

`agentic-proofkit` is intended to provide reusable proof-workflow mechanics for
repositories that want explicit requirements, proof bindings, deterministic
reports, and bounded guidance for coding agents.

Proofkit does not own a consuming repository's product requirements, native
witness execution, receipt authenticity, proof freshness, merge admission,
rollout, deployment, or production readiness.

## Start Here

| Need | Owner |
|---|---|
| Human orientation | This README |
| Coding-agent startup | `AGENTS.md` |
| Adoption and release-channel model | `ADOPTION.md` |
| Completion criteria and remaining work | `BACKLOG.md` |
| Contribution rules | `CONTRIBUTING.md` |
| Vulnerability reporting boundary | `SECURITY.md` |
| Explicit boundary denials | `NON_CLAIMS.md` |
| `LICENSE` | MIT license |

## Non-Claims

This README is a human landing page. It is not a CLI contract, release proof,
package publication claim, security audit, or consumer readiness claim. CLI and
package behavior are owned by their source, tests, machine-readable contracts,
and release evidence, not by this overview.
