# Proofkit Contract Map

Status: maintained consumer routing surface.

Owner: `proofkit`.

## Purpose

This map helps consuming repositories choose the smallest Proofkit CLI command
or JSON contract without loading the full README or source tree. It is not an
exhaustive schema reference. The canonical command inventory is
`proofkit/cli-contract.v2.json`.

Formal rule:

```text
Contract map routes humans and agents.
CLI/JSON records own cross-language behavior.
Go packages implement the shipped executable.
Consumer repositories own product truth, local policy, and native witnesses.
```

Scope-class rule:

```text
Most commands consume explicit caller-owned JSON/input refs.
Explicit filesystem scanners must be named in the CLI contract.
Scanner commands require caller-selected roots or scopes.
No command may infer ambient repository truth from the current directory.
```

## Capability Routes

Exact, non-overlapping CLI navigation membership is owned by
`proofkit/command-families.v1.json` and exposed through `help families` and
`help family <family-id>`. The table below is a cross-cutting capability map:
commands may appear in more than one row because a workflow can cross several
owner boundaries. It is not a second command-family inventory.

| Family | Main commands | Caller provides | Proofkit owns | Consumer owns | Output authority |
|---|---|---|---|---|---|
| Adoption and scaffolding | `init`, `adoption-contract-envelope`, `adoption-workflow-plan`, `adoption-checklist`, `adoption-doctor`, `gradual-adoption`, `gradual-adoption-bootstrap`, `gradual-adoption-guidance`, `capability-map-admission`, `pilot-admission`, `scaffold-profile-plan`, `scaffold-project-structure`, `stack-preset` | adoption intent, aggregate adoption contract envelope, checklist facts, target paths, owner routes, caller-extracted stale authority vocabulary facts, explicit pre-spec capability observations, pilot records, stack preset id, optional init preset id | dry-run route selection, aggregate contract-envelope admission, deterministic starter plans, checklist/report admission, bounded guidance envelopes, dry-run manifests, pre-spec trust-mode admission, adoption gap and stale-authority classification, pilot shape admission | final files, final requirements, rollout policy, text extraction from files, code observation extraction, pilot truth | selected child output, plan, report, seed packet, or agent envelope |
| Requirement source | `capability-map-admission`, `requirement-authoring-plan`, `requirement-source-admission`, `requirement-source-transition`, `spec-overview-claims`, `requirement-spec-tree`, `requirement-spec-tree-view`, `requirement-source-view`, `requirement-browser-server` | `requirements.v1.json`, caller-owned capability maps, caller-owned authoring facts, overview claim extraction, explicit spec hierarchy, view options | candidate seed admission, candidate-only authoring packets, source-shape admission, lifecycle checks, explicit tree topology/source-ref admission, shared safe renderer fragments, presentation-only views | requirement meaning, extraction completeness, Markdown extraction completeness, hierarchy ownership, proof adequacy, file materialization | capability map report, authoring packet, source report, spec-tree report, rendered view, or browser presentation |
| Requirement proof binding | `requirement-bindings`, `binding-partition`, `proof-slice`, `evidence-graph`, `requirement-proof-resolver`, `requirement-proof-source-set`, `requirement-proof-view`, `spec-proof-bundle-admission` | requirement records, bindings, witness commands, source-set facts, receipt reports, partition policy | graph validation, binding partition projection, compact slices, typed compact proof contract projections, resolver projections, bundle linkage checks | test semantics, witness execution, proof freshness, merge policy | proof report, partition report, slice, lookup graph, or view |
| Test inventory and coverage | `test-evidence-inventory`, `test-evidence-inventory --projection discovery-draft`, `test-evidence-inventory --normalized-inventory`, `requirement-coverage-input-compose`, `requirement-coverage-view`, `requirement-browser-server --view coverage` | caller-owned direct or source-set test inventory, caller-owned explicit test discovery facts, declared quality findings, requirement source, proof binding or compact proof contract, coverage universe, optional owner-invariant registry, aggregate coverage compose input | strict inventory/source-set admission, candidate-only discovery draft projection, fail-closed normalized inventory projection, deterministic coverage-view input composition from explicit facts, weak-oracle and declared-quality classification, bounded agent action guidance, requirement/test/command/owner-invariant joins, nonsemantic command-evidence classification, stable coverage failure/warning classifications, presentation-only coverage view | inventory completeness, weak-test truth, test discovery extraction, native test execution, receipt freshness, producer trust, merge policy | candidate inventory guidance, inventory report, normalized inventory data product, coverage-view input, coverage view, or browser presentation |
| Selective planning | `changed-path-set`, `requirement-impact-input-compose`, `impact`, `selective-gate-plan`, `selective-gate-evidence`, `selective-gate-obligation-decision-input`, `proof-obligation-algebra`, `obligation-decision` | changed paths, base/current requirement sources, base/current single-binding-per-requirement proof contracts, generated-artifact policy, local environment policy, proof-like path policy, scan obligation ownership, planned receipts, obligation routes, obligation algebra records | fail-closed impact input composition, fail-closed planning, receipt comparison, obligation algebra admission, bounded agent packets | git diff truth, repository scanning, command execution, producer trust, final admission | composed impact input, plan, evidence report, obligation algebra report, or obligation input |
| Receipts and producers | `proof-receipt-admission`, `receipt-producer-admission`, `receipt-currentness-scope`, `receipt-trust-class`, `producer-policy-self-proof` | receipt sets, producer policy, scope/currentness facts, trust classes | receipt shape, producer/receipt compatibility, self-proof diagnostics | producer authentication, freshness policy, CI trust roots | receipt/provenance report |
| Release and deployment | `release-authority`, `external-consumer`, `registry-consumer-proof-input-compose`, `registry-consumer`, `deployment-evidence-admission`, `completion-criteria`, `branch-authority`, `readiness-closeout` | package facts, tarball/registry facts, explicit primitive registry/install/smoke facts, deployment evidence, criteria, branch facts | artifact/channel boundary checks, registry-consumer input composition, release diagnostics, falsifiable criteria shape | package publication, registry fetch, package-manager execution, deployment, rollback, approval | composed input, release/deployment/readiness report |
| Supply-chain and quality | `self-check`, release workflow, `npm run release:sbom`, `npm run self:coverage`, `npm run go:actionlint`, `npm run go:bench` | release artifacts, source workflows, specs, bindings, witness plans, explicit benchmark invocation | deterministic self-check report shape, SBOM candidate evidence, coverage metrics, workflow lint routing, benchmark entrypoints | public-source provenance, vulnerability triage, license approval, CI run admission, release approval | self-check report, SBOM, metrics report, CI signal, or benchmark output |
| Repository structure | `repo-profile-admission`, `workspace-manifest-facts`, `workspace-registry`, `workspace-changed-package-plan`, `workspace-shard-partition`, `typescript-public-api-surfaces`, `text-policy`, `secret-scan`, `package-runtime-dependency-admission` | explicit repo/profile facts, caller-owned manifest records, caller-owned roots, caller-owned text file inventories, explicit TypeScript package-manifest and per-condition source paths, optional `environmentClassPolicies` tuples | structural admission, manifest-to-workspace fact projection, workspace graph projections, bounded TypeScript package public API checks over referenced files, text policy admission, explicit-inventory secret-like text detection, shard plans | repository freshness, git/file discovery, compiler output provenance, command policy, package manager truth, provider secret scanning | structural, fact, policy, or planning report |
| Custom and generated artifacts | `custom-rule-boundary`, `document-lifecycle-boundary`, `rendered-artifact-freshness`, `conformance-profile`, `json-report-cli-adapter-source`, `witness-plan`, `witness-scheduler-plan` | custom rule metadata, document lifecycle records, artifact digests, profile manifests, command metadata, adapter language | boundary checks, generated-view freshness shape, deterministic adapter source generation, scheduler metadata checks | rule execution, document meaning, cache contents, CI scheduling, committed generated-source freshness | boundary report, generated source artifact, or scheduler report |
| CLI metadata | `help` | optional command name or help flag | built-in command catalog and help text routing | command selection, semantic proof, freshness, merge policy | text help only |

## Migrating Repository Route

For imperfect repositories, use Proofkit as a transition toolkit rather than a
semantic judge.

```text
inventory facts from caller
  -> adoption workflow or bootstrap guidance
  -> owner-selected boundary
  -> requirement source admission
  -> proof-binding validation
  -> native witnesses plus contract tests
  -> selective plan and admitted receipts
```

Route ambiguous modernization work through the smallest matching family:

| Question | First route | Why |
|---|---|---|
| No specs exist and current code should be frozen as the first baseline. | `capability-map-admission` with `trustMode: "code_baseline"` | It admits caller-owned capability observations and emits bounded candidate requirement/proof-binding seeds only when scenarios have candidate ids and executable anchors. |
| No specs exist and current code is not trusted. | `capability-map-admission` with `trustMode: "audit_from_code"` | It treats code observations as hypotheses, keeps missing anchors as owner actions, and prevents code from becoming stable requirement truth without owner review. |
| Where should adoption start? | `adoption-workflow-plan` or `scaffold-project-structure`; use `adoption-contract-envelope` when one caller-owned aggregate adoption file already exists. | They route scenario steps and first-module starter records without scanning the repository; the aggregate route removes consumer-local root-key projection scripts without owning rollout policy. |
| Is a candidate module ready for gradual enforcement? | `gradual-adoption-guidance` | It reports missing source, binding, witness, blocked-precondition, and advisory candidate-boundary facts by adoption mode. |
| What still blocks an imperfect repository from enforcement? | `adoption-doctor` | It classifies caller-provided owner routes, candidate boundaries, child reports, blocked preconditions, and stale current authority vocabulary facts without scanning repository state or owning semantic boundary decisions. |
| Does current documentation still name a retired proof package or proof owner? | `adoption-doctor --agent-envelope` with caller-extracted `staleAuthority` facts | It fails current authority surfaces, admits only explicitly scoped historical vocabulary, and emits bounded repair actions without substring-scanning files itself. |
| Can old local proof infrastructure be retired? | `migration-parity-admission` then `migration-plan` | Parity evidence and post-retirement validation are required before retirement actions appear. |
| Did a requirement move, split, or retire correctly? | `requirement-source-transition` | Requirement lifecycle and replacement ids belong to source transition, not proof binding. |
| Should temporary external design or PR facts become candidate requirements? | `requirement-authoring-plan` | It packages caller-owned extracted facts into candidate-only updates and owner-review questions without writing source files, retaining design documents, or approving meaning. |
| Does a `REQ-*` have a route to execution? | `requirement-bindings` or `proof-slice` | Proof bindings own route closure, while tests own executable behavior. |
| Tests were discovered from an existing repository but are not yet admitted proof evidence. | `test-evidence-inventory --projection discovery-draft` | It accepts explicit caller-owned discovery facts and emits candidate-only inventory guidance with a non-strict candidate authority. Stop before treating candidates as semantic coverage; the consumer must materialize strict test inventory rows. |
| Which checks should run for a change? | `selective-gate-plan` then `selective-gate-evidence` | Planning and receipt comparison stay separate from command execution. |
| Does the selective plan need a text or secret scan? | Use `scanObligation` with `commandOwnership: "proofkit_text_policy"` for `text-policy`, `commandOwnership: "proofkit_secret_scan"` for `secret-scan`, or `commandOwnership: "caller_owned_external"` for an external scanner. | Stop before treating any inventory command as repository-wide discovery. Proofkit admits scan obligations but does not execute scanner commands or prove repository-wide credential absence. `secret-scan` suppressions must match exact finding class, path, and line; stale suppressions fail closed. |

## Agent Decision Procedure

Agents should use `agent-route` for executable routing and
`agent-route --agent-envelope` when a bounded work packet is needed. The command
returns deterministic JSON from explicit caller-owned facts; the envelope is an
opt-in derived projection over the same report. This map explains the route
families without becoming an execution, freshness, or merge decision.
The exact route input vocabulary is machine-readable in
`proofkit/cli-contract.v2.json` under `agent-route.inputContract`; the Go
admission implementation and shipped CLI contract are parity-tested.

Formal rule:

```text
goal plus caller-owned state
  -> smallest matching command family
  -> explicit required input
  -> deterministic report or bounded envelope
  -> caller-owned execution, proof freshness, and merge decision
```

Decision tree:

Semantic context routes are `requirement-context-compose`,
`requirement-context-slice`, `requirement-semantic-diff`, and
`requirement-traceability-graph`.

| State or goal | Next Proofkit route | Stop or escalation condition |
|---|---|---|
| The agent does not know where to start. | `init` or `init --preset fresh|code-baseline|code-audit|legacy|change-set` | Treat output as dry-run route guidance only. Stop before scanning, writing files, or making requirements authoritative. |
| No admitted spec/profile exists and the caller has explicit capability observations. | `capability-map-admission`; use `trustMode: "code_baseline"` only when maintainers intentionally freeze current code, otherwise use `trustMode: "audit_from_code"`. | Stop before treating seeds as stable requirements. The consumer owns observation extraction, materialization, requirement meaning, and proof adequacy. |
| No admitted spec/profile exists and no capability observations exist. | `scaffold-project-structure`, `adoption-workflow-plan`, or `stack-preset` | Stop before writing files; the consumer owns materialization, overwrite policy, and final requirement text. |
| Candidate boundary is uncertain. | `adoption-doctor` or `gradual-adoption-guidance --agent-envelope` | Escalate to owner review when the boundary is advisory, ambiguous, or missing native witnesses. |
| Temporary external design, implementation-plan, PR, code, or test observations may contain durable requirements. | `requirement-authoring-plan` | Treat output as candidate-only; stop before writing `requirements.v1.json`, retaining temporary documents, or claiming requirement meaning. |
| Requirement records exist. | `requirement-source-admission`; use `requirement-source-transition` for lifecycle changes. | Escalate when blocking requirements lack proof routes or lifecycle replacement ids are incomplete. |
| Humans or agents need meta/module/submodule navigation. | `requirement-spec-tree`, then `requirement-spec-tree-view` or `requirement-browser-server --view spec-tree` from the same caller-owned tree input. | Stop before inferring hierarchy from paths. The consumer owns source hierarchy; CLI/browser outputs remain presentation only and are not committed by default. |
| An agent needs a bounded semantic subset instead of whole specification files. | `requirement-context-compose --repo-root <caller-selected-root>` over an explicit catalog, then `requirement-context-slice` over the materialized snapshot. | The snapshot and slice are content-bound derived projections. Stop before inferring hierarchy, scanning ambient paths, treating omissions as absence, or promoting the slice to requirement, proof, freshness, or merge authority. |
| Overview prose may contain durable claims. | `spec-overview-claims` | Escalate when normative claims are not tied to `REQ-*` records. |
| Requirements have no verified proof route. | `requirement-bindings`, `witness-plan` from either an explicit `witness_command_catalog` or a complete `binding_witness_plan_input`, `proof-slice`, or `requirement-proof-resolver` | Stop before claiming proof adequacy; native witness semantics stay with the consumer. A binding-derived witness plan still needs caller-owned vocabulary and conservative command policy. |
| Tests or proof evidence need inventory. | `test-evidence-inventory`; use `--projection discovery-draft` only for explicit discovered-test facts, then `requirement-coverage-input-compose` when an aggregate `coverage_compose_input` exists, then `requirement-coverage-view` when a `coverage_view_input` exists | Compose only from explicit caller-owned facts. Discovery drafts are candidate-only and cannot close coverage. Use `failureClassifications[]`, `warningClassifications[]`, and `agentActionPlan[]` for machine routing. Escalate when tests are route-only, weak-oracle, unbound, or outside the caller-owned coverage universe. |
| A change set is known. | `changed-path-set`, optionally `requirement-impact-input-compose`, `impact`, then `selective-gate-plan --agent-envelope` | Raw `knownChangedPaths` in `agent-route` are diagnostic only. Materialize a caller-owned `changed_path_set`, compose a caller-owned `impact_input` before `impact`, and compose a caller-owned `selective_gate_plan_input` before `selective-gate-plan`. Use `scanObligation` to name whether a `text-policy`, `secret-scan`, or caller-owned external scanner is required. Fail closed on unknown scope, dynamic edges, missing owner routes, unbound proof-like paths, or full-gate escalation. |
| Caller-owned file contents need secret-like text detection. | `secret-scan` | Provide explicit sorted file inventory with content. Stop before claiming repository-wide discovery, credential validity, provider ingestion, merge readiness, or replacement of GitHub secret scanning. |
| Does a TypeScript package public API match a caller-owned manifest? | `agent-route` with `goal: "verify_typescript_public_api"` and explicit `typescript_public_api_manifest` plus `typescript_public_api_repo_root`, then `typescript-public-api-surfaces --repo-root <caller-selected-root>` | The manifest must name each referenced `package.json`, sorted-unique export conditions, and a non-JSX `.ts`, `.mts`, or `.cts` `sourcePath` whose canonical target has the same admitted extension class. The bounded scanner accepts only the fail-closed export grammar in `proofkit/cli-contract.v2.json`; it does not parse unrestricted TypeScript or TSX, infer conventional layouts, or prove compiler output provenance, checkout freshness, package-manager truth, or merge readiness. |
| Receipts are available for planned checks. | `selective-gate-evidence --agent-envelope`; then materialize a caller-owned `obligation_decision_input` from the evidence output plus command routes, currentness, and trust facts; then run `selective-gate-obligation-decision-input`; then materialize the resulting `obligation_decision` input and run `obligation-decision --agent-envelope` | Escalate on missing, stale, invalid, untrusted, blocked, unavailable, or unknown-scope evidence. |
| Human inspection, semantic comparison, or traceability navigation is needed. | `requirement-source-view`, `requirement-proof-view`, `requirement-coverage-view`, `requirement-spec-tree-view`, `requirement-semantic-diff`, `requirement-traceability-graph`, or `requirement-browser-server` | Semantic diff compares admitted owner fields rather than lines. Traceability keeps specification, proof, code, and native execution evidence planes separate. Browser and rendered outputs remain presentation only unless the consumer admits a tracked artifact freshness gate. |
| Temporary external document lifecycle facts, generated views, or rendered views need authority classification. | `document-lifecycle-boundary` | Treat lifecycle records as caller-owned metadata. Temporary design docs and implementation plans are not retained repository authority unless rewritten into deterministic specs, proof bindings, tests, package-public docs, or backlog rows. |
| A JavaScript/TypeScript consumer needs less wrapper code. | `json-report-cli-adapter-source --language typescript --format json` | Generated adapter source is caller-owned after materialization. The consumer still owns package pin, binary path, repo paths, local policy, and freshness proof. It is a CLI runner adapter, not a separate SDK authority. |
| A Python consumer needs Proofkit from Python tooling. | Install the Python package when available and invoke the same CLI/JSON contract. | The Python package is a runner wrapper over the Go CLI, not a Python SDK or alternate schema owner. |
| Local proof infrastructure may be retired. | `migration-parity-admission`, then `migration-plan` | Stop before deleting local owners unless parity and post-retirement validation are caller-approved. |
| Release, package, or deploy evidence is in scope. | `release-authority`, `registry-consumer-proof-input-compose`, `registry-consumer`, `external-consumer`, `deployment-evidence-admission`, or `readiness-closeout` | Compose registry-consumer input from explicit primitive facts first when needed; final registry-consumer validation remains separate. Treat registry, release, CI, deployment, and readiness evidence as separate classes. |
| The agent does not know which route applies. | `agent-route` with a known goal, or this map when no route input exists yet. | Escalate to the consumer owner instead of guessing, scanning ambient state, or executing commands. |

## Routing Rules

1. Start from `proofkit/cli-contract.v2.json` when a machine needs the exact
   command, flags, input mode, output mode, scope class, or `agent-route` input
   contract.
2. Start from this map when a human or agent only needs the correct command
   family.
3. Use `agent-route` when a coding agent needs a deterministic next-command
   packet from explicit current state. Use `agent-route --agent-envelope` when
   the agent needs compact context refs, blockers, command refs, and non-claims
   instead of a plain route report. Treat `blocked_*` states as stop signals,
   not as permission to guess missing inputs. `knownChangedPaths` are
   diagnostic-only until the caller supplies a `changed_path_set`; browser
   server startup requires explicit `browserMode: "serve_local_view"`.
4. Use agent-envelope output only when a coding agent needs bounded context;
   do not expand whole proof graphs into chat.
5. Treat generated views and rendered HTML as presentation only. They never
   replace the structured source record.
6. Escalate to the consuming repository's owner policy whenever Proofkit reports
   unknown scope, missing receipts, unavailable preconditions, or command
   execution requirements.
7. Treat candidate boundaries from imperfect repositories as advisory until the
   consuming repository commits stable requirement records and proof bindings.

## Contract Classification

Contract ceremony is determined by independent consumer-owned dimensions, not
by an inferred universal tier:

| Dimension | Cardinality | Typical values |
|---|---|---|
| `authorityClasses[]` | sorted set | `trust_boundary`, `public_contract`, `internal_behavior`, `derived_artifact` |
| `stabilityClass` | exactly one | `durable`, `evolutionary`, `local`, `generated` |
| `enforcementClass` | exactly one | `blocking`, `advisory`, `derived` |
| `evidenceClasses[]` | sorted set | `dedicated_binding`, `shared_native_test`, `rendered_freshness` |

Set-valued classes may coexist: a public API can also be a trust boundary, and
a generated view can also be a public contract. Proofkit admits explicit facts
and mechanics; it does not infer requirement meaning, a contract profile, or
ceremony from prose, `riskClass`, `claimLevel`, or code layout. A future
machine-readable classification field requires its own versioned caller-owned
contract and producer-to-consumer round-trip proof.

## Omitted Surfaces

This map intentionally omits exhaustive per-field schema documentation,
generated view instances, generated graph instances, receipt instances, and
language-specific wrapper APIs. Those surfaces are either generated on demand,
owned by the caller, or derived from the CLI/JSON contracts.
