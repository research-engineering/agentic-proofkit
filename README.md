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
| Source repository | Declared in package metadata; provider visibility is a live GitHub fact |
| Current layer | Public-source workflow; release evidence is version-specific |
| Runtime implementation | Go CLI with npm and Python wrapper packaging |
| Package release | Scoped npm release channel configured; exact version and registry identity are owned by npm and GitHub Release artifacts |
| Public-source provenance | Claimed only for a version whose release assets, registry identity, and checksum manifests are artifact-closed |
| License | MIT |

## Install

The canonical registry identity is npm:

```bash
npm install -D @research-engineering/agentic-proofkit
```

Bun consumers may install the same npm registry package with Bun:

```bash
bun add -d @research-engineering/agentic-proofkit
```

npm remains the release-authority toolchain because release proof records npm
registry identity, `dist.integrity`, `dist.shasum`, `npm pack`, and root-only
registry install evidence. Bun is a supported consumer/developer package
manager path, not a replacement for npm release evidence.

## Project Boundary

`agentic-proofkit` is intended to provide reusable proof-workflow mechanics for
repositories that want explicit requirements, proof bindings, deterministic
reports, and bounded guidance for coding agents.

Proofkit does not own a consuming repository's product requirements, native
witness execution, receipt authenticity, proof freshness, merge admission,
rollout, deployment, or production readiness.

## How It Works

Proofkit has two related but separate loops:

- an **authoring loop** for turning observations into candidate invariants and
  repo-owned specifications;
- a **proof loop** for admitting those specifications, binding them to evidence,
  and producing derived views or bounded next actions.

The loops are separate because generated observations are not product truth.
Only the consuming repository can promote a candidate invariant into an
admitted requirement.

### Proof Loop

```mermaid
flowchart TB
    subgraph Repo["Consumer repository authority"]
        Requirements["Requirements and invariants"]
        Bindings["Proof bindings and witness commands"]
        Execution["Native test and CI execution"]
        Decision["Owner decision"]
    end

    subgraph Proofkit["Proofkit reusable mechanics"]
        Admission["Admit and normalize JSON"]
        Graph["Build proof graph"]
        Planning["Plan selected checks"]
        Receipts["Admit receipt-shaped evidence"]
        Views["Render derived views"]
        Packets["Emit bounded agent packets"]
    end

    Requirements --> Admission
    Bindings --> Admission
    Admission --> Graph
    Graph --> Planning
    Planning --> Execution
    Execution --> Receipts
    Receipts --> Decision
    Graph --> Views
    Graph --> Packets
    Views --> Decision
    Packets --> Decision
```

The core invariant is separation of authority. The consuming repository owns
what the product must do and which native checks prove it. Proofkit owns the
reusable mechanics: admitting structured inputs, preserving provenance,
checking proof-binding shape, planning bounded verification, rendering derived
views, and returning agent-readable next-action packets.

The diagram keeps the rendering syntax intentionally simple for GitHub README
compatibility. Requirements, bindings, witness commands, native execution, and
final decisions stay in the consumer repository. Proofkit outputs are admitted
reports, plans, views, receipts, or agent packets; they do not become product
truth unless the consumer explicitly admits them.

### Invariant Authoring Loop

For a repository with no specification, Proofkit can guide an agent through two
different starting modes:

```mermaid
flowchart TB
    Start["Code, docs, tests, issues, and maintainer intent"] --> Mode["Choose trust mode"]
    Mode --> Baseline["Code baseline mode"]
    Mode --> Audit["Code audit mode"]
    Baseline --> Observations["Caller-owned capability observations"]
    Audit --> Observations
    Observations --> Seeds["Candidate invariants and requirement seeds"]
    Seeds --> Review["Owner review and promotion"]
    Review --> Specs["Repo-owned requirements.v1.json"]
    Specs --> Obligations["Proof obligations"]
    Obligations --> Evidence["Proof bindings and test inventory"]
    Evidence --> Admission["Proofkit admission and coverage"]
```

| Mode | Use when | Result |
|---|---|---|
| Code baseline | Current behavior is accepted as the starting contract | Candidate requirements and bindings that preserve current behavior until owners review them |
| Code audit | Current behavior may be wrong or incomplete | Untrusted observations and questions that must be promoted by a repository owner before becoming requirements |

In both modes, generated records remain candidates until the consuming
repository admits them as repo-owned requirements, proof bindings, and witness
plans. Proofkit can structure and validate candidate packets, but it does not
extract complete behavior from arbitrary source code, invent product policy, or
make generated invariants authoritative by itself.

## Start Here

| Need | Owner |
|---|---|
| Human orientation | This README |
| Coding-agent startup | `AGENTS.md` |
| Adoption and release-channel model | `ADOPTION.md` |
| Active work ledger | `BACKLOG.md` |
| Contribution rules | `CONTRIBUTING.md` |
| Vulnerability reporting boundary | `SECURITY.md` |
| Explicit boundary denials | `NON_CLAIMS.md` |
| `LICENSE` | MIT license |

## Non-Claims

This README is a human landing page. It is not a CLI contract, release proof,
package publication claim, security audit, or consumer readiness claim. CLI and
package behavior are owned by their source, tests, machine-readable contracts,
and release evidence, not by this overview.
