# agentic-proofkit

Reusable CLI and JSON proof infrastructure for agentic software repositories.

The current repository layer defines project governance, contribution rules,
security reporting, and non-claims. Runtime code, machine-readable CLI
contracts, specifications, package metadata, and release workflows are separate
authority layers and are not claimed by this layer.

## Current Repository State

| Surface | State |
|---|---|
| Source visibility | Public-source release provenance is not claimed by this layer |
| Current layer | Public project contract |
| Runtime implementation | Not claimed by this layer |
| Package release | Not claimed by this repository state |
| Public-source provenance | Not claimed until a reviewed release is produced from public source |
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
| Contribution rules | `CONTRIBUTING.md` |
| Vulnerability reporting boundary | `SECURITY.md` |
| Explicit boundary denials | `NON_CLAIMS.md` |
| `LICENSE` | MIT license |

## Non-Claims

This README is a human landing page. It is not a CLI contract, release proof,
package publication claim, security audit, or consumer readiness claim. Runtime
and package behavior are not claimed until the corresponding source, contracts,
tests, and release evidence are imported and reviewed.
