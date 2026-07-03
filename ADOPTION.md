# Adoption Contract

`agentic-proofkit` is a reusable CLI and JSON infrastructure dependency for
agentic proof workflows. Consuming repositories may use it only as a mechanics
owner: it validates, renders, plans, and packages explicit caller-owned records.
It does not own product meaning, native witness execution, proof freshness,
merge admission, rollout, deployment, or production readiness.

Formal dependency-readiness predicate:

```text
external dependency ready :=
  exact package artifact identity
  and package gate evidence
  and installed CLI binary consumer contract
  and explicit rollback path
  and channel-specific authority
```

Source presence, an open pull request, a dry-run package artifact, or a GitHub
Release archive is not enough to satisfy this predicate.

## Distribution Channels

Public npm is the primary package-manager channel for JavaScript, TypeScript,
Bun, and other Node-package consumers. The npm package identity is
`@research-engineering/agentic-proofkit`; the installed CLI binary remains
`agentic-proofkit`. PyPI is the Python/uv channel after its own Trusted
Publisher and post-publish registry identity are admitted. GitHub Release
assets are archive and provenance lookup, not package-manager dependency
authority.

Stable authority channel ids:

| Channel | Authority owner | Non-claims |
|---|---|---|
| `tarball_pilot` | exact local root package tarball produced by the package artifact gate | source checkout, registry release, consumer rollout |
| `registry_release` | public npm registry identity captured by the release workflow for tag `v<version>` | consumer dependency admission, native witness pass, rollout |
| `python_wheel_candidate` | platform wheels produced from the same Go CLI candidate | PyPI registry authority, consumer install proof |
| `pypi_registry_release` | PyPI JSON identity captured after publish or exact existing-byte match | consumer install proof, rollout |
| `github_release_archive` | GitHub Release asset inventory, checksums, SBOM, and retained release metadata | package-manager dependency authority |

Registry publication modes are:

| Mode | Meaning | Non-claim |
|---|---|---|
| `published_by_workflow` | the current release workflow published the candidate bytes through the admitted provider path | provider UI settings are not proven by the local report alone |
| `existing_byte_match` | the registry version already existed and byte-matched the candidate artifact | current-run publisher provenance |
| `mixed` | some files were current-run publications and others were existing byte matches | uniform provenance for every file |

When a channel claims Trusted Publisher or OIDC publication, retained evidence
must name the provider, registry, project name, repository, exact tag workflow
ref, publisher job, environment, and package identity.

## One-Dependency Infrastructure Model

Consumers should not copy Proofkit verifier logic. They should keep only
caller-owned semantic inputs and route reusable mechanics through the CLI:

```text
consumer structured records
  -> proofkit validation and reports
  -> on-demand human rendering
  -> bounded agent slices or envelopes
  -> caller-owned native witnesses and receipts
```

Proofkit may provide:

- schemas and strict JSON admission for caller-owned records;
- immutable canonical projections after admission;
- deterministic reports, view models, and loopback-only browser serving;
- requirement source, proof binding, source-set, test inventory, coverage,
  impact, selective planning, receipt, release, adoption, and scaffold
  primitives;
- bounded agent guidance packets that state required inputs, blockers,
  non-claims, and escalation points.

The consumer still provides:

- product requirement sentences and owners;
- proof-binding content and command policy;
- native witnesses and their execution semantics;
- CI producer admission policy and receipt freshness;
- credential approval, merge admission, rollout, and rollback decisions.

## Imperfect Repository Adoption

Proofkit is not limited to already-perfect repositories. Its generic
responsibility in a messy or modernizing repository is transition discipline.
It can report gaps, stale local proof owners, duplicate proof routes, orphan
tests, candidate boundaries, and migration questions. It must keep candidate
boundaries advisory until the consuming repository promotes them into stable
requirement records and proof bindings.

Safe modernization loop:

```text
caller-provided observations over code, tests, and docs
  -> proofkit inventory, gap report, and agent guidance
  -> owner-selected semantic boundary
  -> stable requirement records
  -> proof-binding contract records
  -> native tests or tools that falsify the requirements
  -> contract tests and validators for proof infrastructure
  -> admitted receipts from caller-approved producers
  -> stronger enforcement mode
```

Adoption modes:

| Mode | Use case | Proofkit role | Consumer decision |
|---|---|---|---|
| `observe` | unknown or messy repository area | inventory, gaps, questions, non-blocking guidance | whether the area is worth specifying |
| `warn` | provisional boundary | visible drift and missing-binding warnings | whether warnings block a PR |
| `enforce-touched` | stabilized touched boundary | fail closed for changed admitted owners | touched-scope completeness and receipts |
| `enforce-all` | fully admitted scope | fail closed for all admitted blocking owners | full coverage claim and rollout |

Candidate boundaries in `observe` and `warn` are advisory. Enforcement modes
fail closed while candidate boundaries remain unresolved because enforcement
requires owner-admitted requirements and proof bindings.

## Requirement, Contract, And Test Order

The durable semantic source is the repository-owned requirement package:
human context in `overview.md` plus machine-admissible `requirements.v1.json`
records. The overview explains context; it does not create uncited durable
truth.

Proof bindings are verification-route contracts. They answer which scenario,
witness, command, environment class, and receipt policy can falsify or support
a requirement. Native tests and tools own executable verification procedures
and observed result semantics. Contract tests and validators prove the proof
infrastructure itself is coherent.

Formal authority order:

```text
Requirement source owns meaning.
Proof binding owns verification route.
Native test or tool owns executable falsifier.
Contract test owns infrastructure consistency.
Receipt owns recorded run facts and provenance.
Merge policy owns admission.
```

Logical creation order for an accepted invariant:

1. Create or update the stable `REQ-*` record.
2. Create or update the proof-binding contract that maps the requirement to
   witness obligations, command ids, environment class, and receipt class.
3. Add or update native tests or tools that can falsify the requirement.
4. Add or update Proofkit contract tests only when the proof infrastructure
   itself changed.
5. Admit receipts only from caller-approved producers.

Tests are not primary semantic authority. A test can prove an invariant only
when the requirement and proof-binding route make the tested obligation
explicit. Some high-level context can remain explanatory, but durable
`must`, `shall`, `guarantee`, or readiness claims must resolve to stable
requirement records or be rejected by the consuming repository's policy.

## Rendering And Browser Views

Rendered HTML, Markdown, lookup graphs, and browser views are presentation
products. They should be generated on demand from explicit caller-owned inputs
unless a consumer explicitly admits a small tracked artifact with a freshness
gate.

Hierarchical rendering must use explicit input:

```text
meta spec
  -> module spec
  -> optional submodule spec
  -> presentation-only tree/view/export
```

Proofkit may render this tree, filter IDs, show linked test scenarios, or
export Markdown/HTML. It must not infer the hierarchy from ambient paths or make
rendered output canonical truth.

## Agent Guidance

Machine-facing reports should provide bounded prompts for coding agents when
that reduces ambiguity. A prompt-like action must identify:

- observed fact;
- uncertainty;
- owner or escalation target;
- exact files, ids, or selectors to inspect;
- candidate action;
- proof command or missing witness;
- non-claim that prevents the guidance from becoming semantic authority.

Agents must stop instead of guessing when ownership, proof freshness, producer
admission, native witness execution, or merge admission is outside Proofkit's
authority.
