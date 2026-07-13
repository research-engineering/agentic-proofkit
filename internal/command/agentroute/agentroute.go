package agentroute

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
)

var (
	goalValues = map[string]struct{}{
		"admit_receipts":                   {},
		"adopt_repository":                 {},
		"author_requirements":              {},
		"bind_requirement_proofs":          {},
		"check_overview_claims":            {},
		"decide_obligations":               {},
		"inspect_coverage":                 {},
		"inspect_requirement_context":      {},
		"inspect_requirement_traceability": {},
		"inventory_tests":                  {},
		"plan_selective_checks":            {},
		"release_or_deploy_evidence":       {},
		"render_human_view":                {},
		"review_requirement_change":        {},
		"retire_local_infrastructure":      {},
		"scaffold_first_module":            {},
		"unknown":                          {},
		"validate_requirement_source":      {},
		"verify_typescript_public_api":     {},
	}
	modeValues      = adoptionmode.ValuesMap()
	inputKindValues = map[string]struct{}{
		"adoption_workflow":                    {},
		"authoring_plan":                       {},
		"binding_witness_plan_input":           {},
		"capability_map":                       {},
		"changed_path_set":                     {},
		"coverage_compose_input":               {},
		"coverage_view_input":                  {},
		"compact_proof_binding":                {},
		"deployment_evidence_input":            {},
		"impact_input":                         {},
		"migration_plan":                       {},
		"migration_parity":                     {},
		"obligation_decision":                  {},
		"obligation_decision_input":            {},
		"overview_claims":                      {},
		"proof_binding":                        {},
		"readiness_closeout_input":             {},
		"registry_consumer_input":              {},
		"release_authority_input":              {},
		"requirement_source":                   {},
		"requirement_source_transition":        {},
		"requirement_context_catalog":          {},
		"requirement_context_repo_root":        {},
		"requirement_context_slice_input":      {},
		"requirement_semantic_diff_input":      {},
		"requirement_traceability_graph_input": {},
		"requirement_workspace_input":          {},
		"scaffold_profile_plan":                {},
		"scaffold_project_structure":           {},
		"selective_evidence":                   {},
		"selective_gate_plan_input":            {},
		"spec_tree_bundle":                     {},
		"test_discovery":                       {},
		"test_inventory":                       {},
		"typescript_public_api_manifest":       {},
		"typescript_public_api_repo_root":      {},
		"witness_command_catalog":              {},
	}
	reportKindValues = map[string]struct{}{
		"adoption":           {},
		"coverage":           {},
		"evidence":           {},
		"obligation":         {},
		"proof_binding":      {},
		"release":            {},
		"requirement_source": {},
		"transition":         {},
	}
	reportStateValues = map[string]struct{}{
		"blocked": {},
		"failed":  {},
		"passed":  {},
		"skipped": {},
		"warning": {},
	}
	browserModeValues = map[string]struct{}{
		"serve_local_view": {},
		"view_plan":        {},
	}
)

const (
	maxRouteIDRunes            = 96
	maxCallerNonClaims         = 8
	maxCallerNonClaimTextRunes = 240
)

type routeInput struct {
	RouteID           string
	Goal              string
	Mode              string
	BrowserMode       string
	OpenBrowser       bool
	AvailableInputs   map[string]string
	KnownChangedPaths []string
	ObservedReports   []observedReport
	CallerNonClaims   []string
}

type observedReport struct {
	Kind  string
	Ref   string
	State string
}

type routeSpec struct {
	RouteFamily     routeFamily
	RequiredAny     [][]string
	RequiredBundles [][]string
	NextCommands    []commandSpec
	StopConditions  []string
	Escalations     []string
	SliceSummary    string
	SliceNonClaims  []string
}

type routeFamily string

const (
	routeFamilyAdoption                 routeFamily = "adoption"
	routeFamilyMigration                routeFamily = "migration"
	routeFamilyReleaseAndDeployment     routeFamily = "release_and_deployment"
	routeFamilyRenderedViews            routeFamily = "rendered_views"
	routeFamilyRepositoryStructure      routeFamily = "repository_structure"
	routeFamilyRequirementProofBinding  routeFamily = "requirement_proof_binding"
	routeFamilyRequirementSource        routeFamily = "requirement_source"
	routeFamilySelectiveEvidence        routeFamily = "selective_evidence"
	routeFamilySelectivePlanning        routeFamily = "selective_planning"
	routeFamilyTestInventoryAndCoverage routeFamily = "test_inventory_and_coverage"
	routeFamilyUnknown                  routeFamily = "unknown"
)

type commandSpec struct {
	Command   string
	InputKind string
	ExtraArgs []string
	ArgInputs []commandArgInput
	Why       string
}

type commandArgInput struct {
	Flag      string
	InputKind string
}

var routeSpecs = map[string]routeSpec{
	"admit_receipts": {
		RouteFamily: routeFamilySelectiveEvidence,
		RequiredAny: [][]string{{"selective_evidence", "obligation_decision_input", "obligation_decision"}},
		NextCommands: []commandSpec{
			{Command: "selective-gate-evidence", InputKind: "selective_evidence", Why: "Receipts must be admitted against the caller-owned selective plan before obligation decisions consume them."},
			{Command: "selective-gate-obligation-decision-input", InputKind: "obligation_decision_input", Why: "Admitted evidence must be projected with caller-owned routes, currentness, and trust context before the final obligation decision."},
			{Command: "obligation-decision", InputKind: "obligation_decision", Why: "Blocking proof obligations must be decided from admitted evidence, not from raw receipt presence."},
		},
		StopConditions: []string{"Stop on missing, stale, invalid, untrusted, blocked, unavailable, or unknown-scope evidence."},
		Escalations:    []string{"Escalate producer trust, freshness, and merge policy to the consuming repository owner."},
		SliceSummary:   "Route receipt facts to evidence admission before obligation decisions.",
		SliceNonClaims: []string{"The selective evidence slice does not authenticate producers or approve merge."},
	},
	"adopt_repository": {
		RouteFamily: routeFamilyAdoption,
		RequiredAny: [][]string{{"adoption_workflow", "capability_map", "scaffold_project_structure"}},
		NextCommands: []commandSpec{
			{Command: "adoption-workflow-plan", InputKind: "adoption_workflow", Why: "Repository adoption should start from a caller-owned workflow plan instead of ambient repository scanning."},
			{Command: "capability-map-admission", InputKind: "capability_map", Why: "Repositories without durable specs may first admit caller-owned code, test, and document observations as candidate-only capability seeds."},
			{Command: "scaffold-project-structure", InputKind: "scaffold_project_structure", Why: "Initial files may be planned as a dry-run scaffold; the caller owns materialization and overwrite policy."},
		},
		StopConditions: []string{"Stop before writing files or claiming module boundaries; Proofkit only returns deterministic adoption guidance."},
		Escalations:    []string{"Escalate boundary selection to the consuming repository owner when candidate surfaces are ambiguous."},
		SliceSummary:   "Route adoption work through explicit workflow plans and dry-run scaffolding.",
		SliceNonClaims: []string{"The adoption slice does not select final module boundaries or write files."},
	},
	"author_requirements": {
		RouteFamily: routeFamilyRequirementSource,
		RequiredAny: [][]string{{"authoring_plan", "capability_map"}},
		NextCommands: []commandSpec{
			{Command: "capability-map-admission", InputKind: "capability_map", Why: "Capability maps convert caller-owned observations into candidate requirement and proof-binding seeds before any stable requirement source is materialized."},
			{Command: "requirement-authoring-plan", InputKind: "authoring_plan", Why: "Temporary design, plan, PR, code, or test observations must become candidate-only requirement updates before owner materialization."},
		},
		StopConditions: []string{"Stop before writing requirements files, approving requirement meaning, or treating candidate previews as stable source authority; after owner materialization, route stable files through validate_requirement_source with a caller-owned requirement source or transition envelope."},
		Escalations:    []string{"Escalate candidate meaning, owner boundary, proof adequacy, native witness execution, and merge policy to the consuming repository owner."},
		SliceSummary:   "Route temporary design and implementation observations into candidate-only requirement authoring packets.",
		SliceNonClaims: []string{"The authoring slice does not infer requirement meaning or materialize stable requirement source files."},
	},
	"bind_requirement_proofs": {
		RouteFamily: routeFamilyRequirementProofBinding,
		RequiredAny: [][]string{{"proof_binding", "binding_witness_plan_input", "witness_command_catalog"}},
		NextCommands: []commandSpec{
			{Command: "requirement-bindings", InputKind: "proof_binding", Why: "Proof bindings own the route from requirements to scenarios, witnesses, commands, and environment classes."},
			{Command: "witness-plan", InputKind: "binding_witness_plan_input", Why: "Binding-derived witness-plan inputs combine admitted proof bindings with witness vocabulary before native command safety is projected."},
			{Command: "witness-plan", InputKind: "witness_command_catalog", Why: "Witness command safety should be checked before native execution is treated as proof evidence."},
			{Command: "proof-slice", InputKind: "proof_binding", Why: "Bounded proof slices give agents local route context without loading full graphs."},
		},
		StopConditions: []string{"Stop before claiming proof adequacy; tests and native witnesses own executable behavior."},
		Escalations:    []string{"Escalate missing semantic owners, weak witnesses, and freshness questions to the consuming repository."},
		SliceSummary:   "Route requirement proof work through bindings, witness plans, and bounded proof slices.",
		SliceNonClaims: []string{"The proof-binding slice does not execute native witnesses or prove semantic adequacy."},
	},
	"check_overview_claims": {
		RouteFamily: routeFamilyRequirementSource,
		RequiredAny: [][]string{{"overview_claims"}},
		NextCommands: []commandSpec{
			{Command: "spec-overview-claims", InputKind: "overview_claims", Why: "Durable overview claims must cite REQ-* records or remain non-normative prose."},
		},
		StopConditions: []string{"Stop when normative overview prose lacks a requirement citation."},
		Escalations:    []string{"Escalate claim extraction completeness to the consuming repository; Proofkit admits the extracted facts only."},
		SliceSummary:   "Route overview claim checks through caller-owned extracted Markdown claim facts.",
		SliceNonClaims: []string{"The overview slice does not parse Markdown or judge product claim adequacy."},
	},
	"decide_obligations": {
		RouteFamily: routeFamilySelectiveEvidence,
		RequiredAny: [][]string{{"obligation_decision"}},
		NextCommands: []commandSpec{
			{Command: "obligation-decision", InputKind: "obligation_decision", Why: "Merge-relevant proof obligations need an explicit decision input instead of raw command results."},
		},
		StopConditions: []string{"Stop on missing, stale, invalid, blocked, deferred, advisory, or not-applicable obligation states."},
		Escalations:    []string{"Escalate final merge admission to the consuming repository owner."},
		SliceSummary:   "Route obligation decisions after evidence has been admitted by its own command.",
		SliceNonClaims: []string{"The obligation slice does not make consumer merge decisions."},
	},
	"inspect_coverage": {
		RouteFamily: routeFamilyTestInventoryAndCoverage,
		RequiredAny: [][]string{{"coverage_compose_input", "coverage_view_input"}},
		NextCommands: []commandSpec{
			{Command: "requirement-coverage-input-compose", InputKind: "coverage_compose_input", Why: "Coverage views should be composed from explicit caller-owned requirement source, proof binding, test inventory, universe, and local environment policy before inspection."},
			{Command: "requirement-coverage-view", InputKind: "coverage_view_input", Why: "Coverage inspection should join admitted requirement, proof-binding, and test-inventory inputs."},
			{Command: "requirement-browser-server", InputKind: "coverage_view_input", ExtraArgs: []string{"--view", "coverage"}, Why: "Browser views are presentation-only inspection surfaces over caller-owned coverage input."},
		},
		StopConditions: []string{"Stop when tests are route-only, weak-oracle, unbound, or outside the caller-owned coverage universe."},
		Escalations:    []string{"Escalate coverage completeness and native test execution to the consuming repository."},
		SliceSummary:   "Route coverage inspection through admitted requirement, proof-binding, and test inventory inputs.",
		SliceNonClaims: []string{"The coverage slice does not claim inventory completeness outside the caller-owned universe."},
	},
	"inspect_requirement_context": {
		RouteFamily:     routeFamilyRenderedViews,
		RequiredBundles: [][]string{{"requirement_context_catalog", "requirement_context_repo_root"}, {"requirement_context_slice_input"}, {"requirement_workspace_input"}},
		NextCommands: []commandSpec{
			{Command: "requirement-context-compose", InputKind: "requirement_context_catalog", ArgInputs: []commandArgInput{{Flag: "--repo-root", InputKind: "requirement_context_repo_root"}}, Why: "An explicit catalog and caller-selected root compose a content-bound semantic context without ambient scanning."},
			{Command: "requirement-context-slice", InputKind: "requirement_context_slice_input", Why: "A materialized slice input selects the smallest bounded reference-closed semantic context."},
			{Command: "requirement-browser-server", InputKind: "requirement_workspace_input", ExtraArgs: []string{"--view", "workspace"}, Why: "A materialized workspace input can be inspected through the presentation-only loopback browser."},
		},
		StopConditions: []string{"Stop before inventing a catalog, repo root, selector, or intermediate operation input; caller materialization owns those transitions."},
		Escalations:    []string{"Escalate specification meaning, source freshness, and omitted semantic classes to the consuming repository owner."},
		SliceSummary:   "Route bounded semantic context inspection through explicit composition, materialized slicing, or a materialized browser workspace.",
		SliceNonClaims: []string{"The semantic context route does not read unlisted files, materialize intermediate JSON, or promote a derived slice to requirement authority."},
	},
	"review_requirement_change": {
		RouteFamily: routeFamilyRenderedViews,
		RequiredAny: [][]string{{"requirement_semantic_diff_input"}},
		NextCommands: []commandSpec{
			{Command: "requirement-semantic-diff", InputKind: "requirement_semantic_diff_input", Why: "A materialized baseline/current diff input preserves owner-declared comparison semantics and snapshot identities."},
		},
		StopConditions: []string{"Stop before fabricating baseline/current snapshots or treating semantic diff as Git, freshness, or merge evidence."},
		Escalations:    []string{"Escalate requirement meaning and acceptance of changes to the consuming repository owner."},
		SliceSummary:   "Route requirement change review through a caller-materialized semantic diff input.",
		SliceNonClaims: []string{"The semantic diff route does not create baselines, read Git, or approve a change."},
	},
	"inspect_requirement_traceability": {
		RouteFamily: routeFamilyRenderedViews,
		RequiredAny: [][]string{{"requirement_traceability_graph_input"}},
		NextCommands: []commandSpec{
			{Command: "requirement-traceability-graph", InputKind: "requirement_traceability_graph_input", Why: "A materialized graph input keeps specification, proof, code traceability, and native execution evidence planes distinct."},
		},
		StopConditions: []string{"Stop before scanning code, inferring topology, authenticating caller-reported evidence, or synthesizing cross-plane coverage."},
		Escalations:    []string{"Escalate code topology, native execution truth, and evidence currentness to their consuming-repository owners."},
		SliceSummary:   "Route traceability inspection through an explicit caller-materialized graph input.",
		SliceNonClaims: []string{"The traceability route does not discover code, execute tests, or turn caller-reported evidence into verified coverage."},
	},
	"inventory_tests": {
		RouteFamily: routeFamilyTestInventoryAndCoverage,
		RequiredAny: [][]string{{"test_discovery", "test_inventory", "coverage_compose_input", "coverage_view_input"}},
		NextCommands: []commandSpec{
			{Command: "test-evidence-inventory", InputKind: "test_discovery", ExtraArgs: []string{"--projection", "discovery-draft"}, Why: "Caller-owned discovered test facts must become candidate-only inventory guidance before any strict semantic inventory is materialized."},
			{Command: "test-evidence-inventory", InputKind: "test_inventory", Why: "Test evidence must be inventoried with semantic oracle and falsifier metadata before coverage views consume it."},
			{Command: "requirement-coverage-input-compose", InputKind: "coverage_compose_input", Why: "Coverage input composition removes consumer-local glue after strict source, binding, inventory, universe, and environment-policy facts exist."},
			{Command: "requirement-coverage-view", InputKind: "coverage_view_input", Why: "Coverage reports should be derived from admitted inventory plus requirement and proof-binding facts."},
		},
		StopConditions: []string{"Stop when discovered tests are candidate-only, or when an inventory entry lacks a semantic oracle, falsifier, command reference, or source selector."},
		Escalations:    []string{"Escalate test intent and native execution to the consuming repository."},
		SliceSummary:   "Route test inventory work from explicit discovery facts to strict semantic evidence records before coverage views consume them.",
		SliceNonClaims: []string{"The test inventory slice does not infer test intent from source code or execute tests."},
	},
	"plan_selective_checks": {
		RouteFamily: routeFamilySelectivePlanning,
		RequiredAny: [][]string{{"changed_path_set", "impact_input", "selective_gate_plan_input"}},
		NextCommands: []commandSpec{
			{Command: "changed-path-set", InputKind: "changed_path_set", Why: "Changed paths must be admitted from caller-owned git facts before impact analysis."},
			{Command: "impact", InputKind: "impact_input", Why: "Impact analysis maps a caller-owned impact input to proof obligations and fail-closed escalation."},
			{Command: "selective-gate-plan", InputKind: "selective_gate_plan_input", Why: "Selective gate planning chooses checks from a caller-owned planner input without executing them."},
		},
		StopConditions: []string{"Fail closed on unknown scope, dynamic edges, missing owner routes, or full-gate escalation."},
		Escalations:    []string{"Escalate command execution and CI scheduling to the consuming repository."},
		SliceSummary:   "Route selective checks from admitted changed-path facts to plans, not execution.",
		SliceNonClaims: []string{"The selective planning slice does not discover git state or run CI commands."},
	},
	"release_or_deploy_evidence": {
		RouteFamily: routeFamilyReleaseAndDeployment,
		RequiredAny: [][]string{{"release_authority_input", "registry_consumer_input", "deployment_evidence_input", "readiness_closeout_input"}},
		NextCommands: []commandSpec{
			{Command: "release-authority", InputKind: "release_authority_input", Why: "Release authority checks package and provenance facts without becoming the publisher."},
			{Command: "registry-consumer", InputKind: "registry_consumer_input", Why: "Registry consumer checks installed artifact facts against caller-owned release evidence."},
			{Command: "deployment-evidence-admission", InputKind: "deployment_evidence_input", Why: "Deployment evidence requires a separate admission route from release packaging."},
			{Command: "readiness-closeout", InputKind: "readiness_closeout_input", Why: "Readiness closeout must remain falsifiable and distinct from deployment execution."},
		},
		StopConditions: []string{"Stop when release, registry, CI, deployment, rollback, or readiness evidence classes are missing or conflated."},
		Escalations:    []string{"Escalate publication, deployment, rollback, and production readiness to the consuming repository."},
		SliceSummary:   "Route release and deployment evidence through separate package, registry, deployment, and readiness reports.",
		SliceNonClaims: []string{"The release slice does not publish packages, deploy services, or approve readiness."},
	},
	"render_human_view": {
		RouteFamily: routeFamilyRenderedViews,
		RequiredAny: [][]string{{"requirement_source", "proof_binding", "compact_proof_binding", "coverage_view_input", "spec_tree_bundle"}},
		NextCommands: []commandSpec{
			{Command: "requirement-source-view", InputKind: "requirement_source", Why: "Human source views render structured requirement records without becoming authority."},
			{Command: "requirement-proof-view", InputKind: "proof_binding", Why: "Human proof views render proof routes without replacing bindings."},
			{Command: "requirement-proof-view", InputKind: "compact_proof_binding", ExtraArgs: []string{"--empty-local-environment-policy"}, Why: "Compact proof views require an explicit local-environment policy before rendering."},
			{Command: "requirement-coverage-view", InputKind: "coverage_view_input", Why: "Coverage views show tests and scenarios linked to requirements."},
			{Command: "requirement-spec-tree-view", InputKind: "spec_tree_bundle", Why: "Spec-tree views render caller-owned hierarchy records without inferring hierarchy from paths."},
			{Command: "requirement-browser-server", InputKind: "requirement_source", ExtraArgs: []string{"--view", "source"}, Why: "The browser server presents caller-owned requirement source inputs over loopback only."},
			{Command: "requirement-browser-server", InputKind: "proof_binding", ExtraArgs: []string{"--view", "proof"}, Why: "The browser server presents caller-owned proof binding inputs over loopback only."},
			{Command: "requirement-browser-server", InputKind: "compact_proof_binding", ExtraArgs: []string{"--empty-local-environment-policy", "--view", "proof"}, Why: "The browser server presents compact proof bindings only with an explicit local-environment policy."},
			{Command: "requirement-browser-server", InputKind: "coverage_view_input", ExtraArgs: []string{"--view", "coverage"}, Why: "The browser server presents caller-owned coverage inputs over loopback only."},
			{Command: "requirement-browser-server", InputKind: "spec_tree_bundle", ExtraArgs: []string{"--view", "spec-tree"}, Why: "The browser server presents caller-owned spec-tree inputs over loopback only."},
		},
		StopConditions: []string{"Stop before treating generated HTML or Markdown as structured source authority."},
		Escalations:    []string{"Escalate tracked rendered-artifact freshness to the consuming repository when generated files are committed."},
		SliceSummary:   "Route human inspection to presentation-only views over caller-owned structured inputs.",
		SliceNonClaims: []string{"The rendered view slice does not make HTML or Markdown canonical authority."},
	},
	"retire_local_infrastructure": {
		RouteFamily: routeFamilyMigration,
		RequiredAny: [][]string{{"migration_parity", "migration_plan"}},
		NextCommands: []commandSpec{
			{Command: "migration-parity-admission", InputKind: "migration_parity", Why: "Local proof infrastructure can be retired only after caller-owned parity evidence is admitted."},
			{Command: "migration-plan", InputKind: "migration_plan", Why: "Retirement actions must be derived from admitted parity and post-retirement validation facts."},
		},
		StopConditions: []string{"Stop before deleting local owners unless parity and post-retirement validation are admitted."},
		Escalations:    []string{"Escalate semantic equivalence and removal approval to the consuming repository."},
		SliceSummary:   "Route local infrastructure retirement through admitted parity before deletion planning.",
		SliceNonClaims: []string{"The migration slice does not approve deletion of consumer-owned proof owners."},
	},
	"scaffold_first_module": {
		RouteFamily: routeFamilyAdoption,
		RequiredAny: [][]string{{"scaffold_profile_plan", "scaffold_project_structure"}},
		NextCommands: []commandSpec{
			{Command: "scaffold-profile-plan", InputKind: "scaffold_profile_plan", Why: "Scaffold profile planning turns caller-reviewed hints into deterministic profile draft data."},
			{Command: "scaffold-project-structure", InputKind: "scaffold_project_structure", Why: "First-module scaffolding should be a dry-run plan; the consumer owns final files."},
		},
		StopConditions: []string{"Stop before writing files, inventing requirement text, or claiming a stable boundary."},
		Escalations:    []string{"Escalate stack, module boundary, and owner choices to the consuming repository."},
		SliceSummary:   "Route first-module setup through dry-run scaffold and profile plans.",
		SliceNonClaims: []string{"The scaffold slice does not invent final requirement text or materialize files."},
	},
	"validate_requirement_source": {
		RouteFamily: routeFamilyRequirementSource,
		RequiredAny: [][]string{{"requirement_source", "requirement_source_transition"}},
		NextCommands: []commandSpec{
			{Command: "requirement-source-admission", InputKind: "requirement_source", Why: "Structured requirement records are the machine-admissible source for requirement state."},
			{Command: "requirement-source-transition", InputKind: "requirement_source_transition", Why: "Lifecycle changes need explicit replacement, evidence, and owner facts."},
		},
		StopConditions: []string{"Stop when blocking active requirements lack proof routes, owners, or lifecycle evidence."},
		Escalations:    []string{"Escalate requirement meaning and proof adequacy to the consuming repository owner."},
		SliceSummary:   "Route requirement source work through machine-admissible records and lifecycle transition checks.",
		SliceNonClaims: []string{"The requirement source slice does not own product meaning or proof adequacy."},
	},
	"verify_typescript_public_api": {
		RouteFamily: routeFamilyRepositoryStructure,
		RequiredAny: [][]string{{"typescript_public_api_manifest"}, {"typescript_public_api_repo_root"}},
		NextCommands: []commandSpec{
			{Command: "typescript-public-api-surfaces", InputKind: "typescript_public_api_manifest", ArgInputs: []commandArgInput{{Flag: "--repo-root", InputKind: "typescript_public_api_repo_root"}}, Why: "This is an explicit filesystem-scan command: it verifies a caller-owned TypeScript public API manifest against a caller-selected checkout root."},
		},
		StopConditions: []string{"Stop before guessing repo roots, discovering package intent, claiming repository freshness, or treating public API verification as merge readiness."},
		Escalations:    []string{"Escalate checkout freshness, package manager truth, command policy, and merge admission to the consuming repository."},
		SliceSummary:   "Route TypeScript public API checks through an explicit manifest plus caller-selected filesystem snapshot.",
		SliceNonClaims: []string{"The TypeScript public API slice does not infer repository intent, prove checkout freshness, or approve merge."},
	},
}

var nonClaims = []any{
	"agent-route selects a deterministic Proofkit command family from explicit caller-owned facts only.",
	"agent-route does not read repository state, execute returned commands, inspect native tests, or write files.",
	"agent-route does not decide product meaning, proof freshness, producer trust, merge, release, rollout, deployment, or production readiness.",
	"A routed state is command-selection evidence only; downstream command reports own their own admission result states.",
}

func Build(raw any) (map[string]any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, 1, err
	}
	if input.Goal == "unknown" {
		return buildUnknownGoal(input), 1, nil
	}
	spec, ok := routeSpecs[input.Goal]
	if !ok {
		return buildUnknownGoal(input), 1, nil
	}
	missing := missingRequiredInputs(spec, input)
	state := "routed"
	exitCode := 0
	blockedReports := blockingObservedReports(input.ObservedReports)
	if len(missing) > 0 {
		state = "blocked_missing_input"
		exitCode = 1
	}
	if len(blockedReports) > 0 {
		state = "blocked_ambiguous_state"
		exitCode = 1
	}
	return buildReport(input, spec, state, missing), exitCode, nil
}

func InputContract() map[string]any {
	return map[string]any{
		"contractId":    "proofkit.agent-route.input.v1",
		"schemaVersion": 1,
		"authority":     "agent-route input admission",
		"fields": map[string]any{
			"schemaVersion": map[string]any{"required": true, "value": 1},
			"routeId": map[string]any{
				"required": true,
				"format":   "safe stable id",
				"maxRunes": maxRouteIDRunes,
			},
			"goal": map[string]any{
				"required": true,
				"enum":     sortedKeys(goalValues),
			},
			"mode": map[string]any{
				"required": true,
				"enum":     sortedKeys(modeValues),
			},
			"browserMode": map[string]any{
				"default":  "view_plan",
				"enum":     sortedKeys(browserModeValues),
				"nonClaim": "serve_local_view only adds --serve to requirement-browser-server routes; it does not create a public server or approve rendered artifacts.",
			},
			"openBrowser": map[string]any{
				"default":  false,
				"nonClaim": "openBrowser only adds --open when browserMode is serve_local_view.",
			},
			"availableInputs": map[string]any{
				"default": []any{},
				"item": map[string]any{
					"kind": map[string]any{"enum": sortedKeys(inputKindValues)},
					"ref":  map[string]any{"format": "safe repo-relative caller-owned file, report ref, or scanner root ref; scanner root refs may be ."},
				},
				"uniqueBy": "kind",
			},
			"knownChangedPaths": map[string]any{
				"default":  []any{},
				"format":   "safe repo-relative paths",
				"nonClaim": "knownChangedPaths is diagnostic-only; selective routing requires a caller-owned changed_path_set input ref.",
			},
			"observedReports": map[string]any{
				"default": []any{},
				"item": map[string]any{
					"kind":  map[string]any{"enum": sortedKeys(reportKindValues)},
					"ref":   map[string]any{"format": "safe repo-relative report ref"},
					"state": map[string]any{"enum": sortedKeys(reportStateValues)},
				},
				"blockingSemantics": "any observed report state other than passed blocks command emission",
				"uniqueBy":          "ref",
			},
			"nonClaims": map[string]any{
				"default":      []any{},
				"maxItems":     maxCallerNonClaims,
				"maxItemRunes": maxCallerNonClaimTextRunes,
			},
		},
		"nonClaims": []any{
			"This input contract describes agent-route admission only.",
			"It does not validate referenced file contents, execute commands, read repositories, or approve merge.",
		},
	}
}

func OutputContract() map[string]any {
	return map[string]any{
		"contractId":    "proofkit.agent-route.output.v2",
		"schemaVersion": 2,
		"authority":     "deterministic route report derived from admitted agent-route input",
		"requiredFields": []any{
			"guidanceSlice",
			"reportId",
			"reportKind",
			"schemaVersion",
			"selectedRouteFamily",
			"state",
		},
		"fields": map[string]any{
			"schemaVersion": map[string]any{"value": 2},
			"selectedRouteFamily": map[string]any{
				"enum": routeFamilyContractValues(),
			},
			"guidanceSlice": map[string]any{
				"requiredFields":  []any{"routeFamily"},
				"routeFamilyRule": "must equal selectedRouteFamily",
			},
		},
		"changesFromV1": []any{
			"selectedFamily is replaced by selectedRouteFamily",
			"guidanceSlice.family is replaced by guidanceSlice.routeFamily",
		},
	}
}

func routeFamilyContractValues() []any {
	values := map[string]struct{}{string(routeFamilyUnknown): {}}
	for _, spec := range routeSpecs {
		values[string(spec.RouteFamily)] = struct{}{}
	}
	return sortedKeys(values)
}

func admitInput(raw any) (routeInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return routeInput{}, fmt.Errorf("agent route input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"availableInputs", "browserMode", "goal", "knownChangedPaths", "mode", "nonClaims", "observedReports", "openBrowser", "routeId", "schemaVersion"}, "agent route input"); err != nil {
		return routeInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return routeInput{}, fmt.Errorf("agent route schemaVersion must be 1")
	}
	routeID, err := admit.RuleID(record["routeId"], "agent route routeId")
	if err != nil {
		return routeInput{}, err
	}
	if len([]rune(routeID)) > maxRouteIDRunes {
		return routeInput{}, fmt.Errorf("agent route routeId must contain at most %d runes", maxRouteIDRunes)
	}
	goal, err := admit.Enum(record["goal"], goalValues, "agent route goal")
	if err != nil {
		return routeInput{}, err
	}
	mode, err := adoptionmode.Admit(record["mode"], "agent route mode")
	if err != nil {
		return routeInput{}, err
	}
	browserMode, err := admitOptionalEnum(record["browserMode"], browserModeValues, "agent route browserMode", "view_plan")
	if err != nil {
		return routeInput{}, err
	}
	openBrowser, err := admitOptionalBool(record["openBrowser"], "agent route openBrowser")
	if err != nil {
		return routeInput{}, err
	}
	if openBrowser && browserMode != "serve_local_view" {
		return routeInput{}, fmt.Errorf("agent route openBrowser requires browserMode serve_local_view")
	}
	availableInputs, err := admitAvailableInputs(record["availableInputs"])
	if err != nil {
		return routeInput{}, err
	}
	observedReports, err := admitObservedReports(record["observedReports"])
	if err != nil {
		return routeInput{}, err
	}
	knownChangedPaths, err := admitOptionalPaths(record["knownChangedPaths"])
	if err != nil {
		return routeInput{}, err
	}
	callerNonClaims, err := admitOptionalCallerNonClaims(record["nonClaims"])
	if err != nil {
		return routeInput{}, err
	}
	return routeInput{
		RouteID:           routeID,
		Goal:              goal,
		Mode:              mode,
		BrowserMode:       browserMode,
		OpenBrowser:       openBrowser,
		AvailableInputs:   availableInputs,
		KnownChangedPaths: knownChangedPaths,
		ObservedReports:   observedReports,
		CallerNonClaims:   callerNonClaims,
	}, nil
}

func admitOptionalEnum(raw any, values map[string]struct{}, context string, defaultValue string) (string, error) {
	if raw == nil {
		return defaultValue, nil
	}
	return admit.Enum(raw, values, context)
}

func admitOptionalBool(raw any, context string) (bool, error) {
	if raw == nil {
		return false, nil
	}
	value, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean", context)
	}
	return value, nil
}

func admitAvailableInputs(raw any) (map[string]string, error) {
	if raw == nil {
		return map[string]string{}, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("agent route availableInputs must be an array")
	}
	result := map[string]string{}
	for index, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("agent route availableInputs[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"kind", "ref"}, fmt.Sprintf("agent route availableInputs[%d]", index)); err != nil {
			return nil, err
		}
		kind, err := admit.Enum(record["kind"], inputKindValues, fmt.Sprintf("agent route availableInputs[%d].kind", index))
		if err != nil {
			return nil, err
		}
		refText, err := admit.NonEmptyText(record["ref"], fmt.Sprintf("agent route availableInputs[%d].ref", index))
		if err != nil {
			return nil, err
		}
		ref, err := admitAvailableInputRef(kind, refText, fmt.Sprintf("agent route availableInputs[%d].ref", index))
		if err != nil {
			return nil, err
		}
		if _, exists := result[kind]; exists {
			return nil, fmt.Errorf("agent route availableInputs must contain unique input kinds")
		}
		result[kind] = ref
	}
	return result, nil
}

func admitAvailableInputRef(kind string, value string, context string) (string, error) {
	if (kind == "typescript_public_api_repo_root" || kind == "requirement_context_repo_root") && value == "." {
		return value, nil
	}
	return admit.SafeRepoRelativePath(value, context)
}

func admitObservedReports(raw any) ([]observedReport, error) {
	if raw == nil {
		return []observedReport{}, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("agent route observedReports must be an array")
	}
	reports := []observedReport{}
	for index, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("agent route observedReports[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"kind", "ref", "state"}, fmt.Sprintf("agent route observedReports[%d]", index)); err != nil {
			return nil, err
		}
		kind, err := admit.Enum(record["kind"], reportKindValues, fmt.Sprintf("agent route observedReports[%d].kind", index))
		if err != nil {
			return nil, err
		}
		state, err := admit.Enum(record["state"], reportStateValues, fmt.Sprintf("agent route observedReports[%d].state", index))
		if err != nil {
			return nil, err
		}
		refText, err := admit.NonEmptyText(record["ref"], fmt.Sprintf("agent route observedReports[%d].ref", index))
		if err != nil {
			return nil, err
		}
		ref, err := admit.SafeRepoRelativePath(refText, fmt.Sprintf("agent route observedReports[%d].ref", index))
		if err != nil {
			return nil, err
		}
		reports = append(reports, observedReport{Kind: kind, Ref: ref, State: state})
	}
	sort.Slice(reports, func(left int, right int) bool {
		return reports[left].Ref < reports[right].Ref
	})
	for index := 1; index < len(reports); index++ {
		if reports[index-1].Ref == reports[index].Ref {
			return nil, fmt.Errorf("agent route observedReports refs must be unique")
		}
	}
	return reports, nil
}

func admitOptionalPaths(raw any) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	return admit.PreserveSortedPathArray(raw, "agent route knownChangedPaths", true)
}

func admitOptionalSortedText(raw any, context string) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	return admit.PreserveSortedTextArray(raw, context, true)
}

func admitOptionalCallerNonClaims(raw any) ([]string, error) {
	values, err := admitOptionalSortedText(raw, "agent route nonClaims")
	if err != nil {
		return nil, err
	}
	if len(values) > maxCallerNonClaims {
		return nil, fmt.Errorf("agent route nonClaims must contain at most %d entries", maxCallerNonClaims)
	}
	for index, value := range values {
		if len([]rune(value)) > maxCallerNonClaimTextRunes {
			return nil, fmt.Errorf("agent route nonClaims[%d] must contain at most %d runes", index, maxCallerNonClaimTextRunes)
		}
	}
	return values, nil
}

func missingRequiredInputs(spec routeSpec, input routeInput) []map[string]any {
	missing := []map[string]any{}
	if len(spec.RequiredBundles) > 0 && !anyInputBundleSatisfied(spec.RequiredBundles, input.AvailableInputs) {
		bundles := make([]any, 0, len(spec.RequiredBundles))
		for _, bundle := range spec.RequiredBundles {
			values := make([]any, len(bundle))
			for index, value := range bundle {
				values[index] = value
			}
			bundles = append(bundles, values)
		}
		missing = append(missing, map[string]any{"oneOfBundles": bundles, "reason": "The selected route requires one complete caller-owned input bundle before a safe next command can run."})
	}
	for _, group := range spec.RequiredAny {
		if inputGroupSatisfied(group, input.AvailableInputs) {
			continue
		}
		if len(group) == 1 {
			reason := "The selected route requires this caller-owned input before a safe next command can run."
			if group[0] == "changed_path_set" && len(input.KnownChangedPaths) > 0 {
				reason = "Raw knownChangedPaths are diagnostic-only; materialize and provide a caller-owned changed_path_set input before selective routing."
			}
			missing = append(missing, map[string]any{
				"kind":   group[0],
				"reason": reason,
			})
			continue
		}
		if inputKindGroupContains(group, "changed_path_set") && len(input.KnownChangedPaths) > 0 {
			missing = append(missing, map[string]any{
				"oneOf":  []any{"changed_path_set", "impact_input", "selective_gate_plan_input"},
				"reason": "Raw knownChangedPaths are diagnostic-only; materialize caller-owned changed_path_set, impact_input, or selective_gate_plan_input before selective routing.",
			})
			continue
		}
		values := make([]any, 0, len(group))
		for _, value := range group {
			values = append(values, value)
		}
		missing = append(missing, map[string]any{
			"oneOf":  values,
			"reason": "The selected route requires one of these caller-owned inputs before a safe next command can run.",
		})
	}
	return missing
}

func anyInputBundleSatisfied(bundles [][]string, available map[string]string) bool {
	for _, bundle := range bundles {
		complete := true
		for _, kind := range bundle {
			if _, ok := available[kind]; !ok {
				complete = false
				break
			}
		}
		if complete {
			return true
		}
	}
	return false
}

func inputKindGroupContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func inputGroupSatisfied(group []string, available map[string]string) bool {
	for _, kind := range group {
		if _, ok := available[kind]; ok {
			return true
		}
	}
	return len(group) == 0
}

func buildUnknownGoal(input routeInput) map[string]any {
	spec := routeSpec{
		RouteFamily:  routeFamilyUnknown,
		SliceSummary: "Unknown goals are deliberately not routed.",
		SliceNonClaims: []string{
			"The unknown-goal slice does not choose commands from ambiguous caller intent.",
		},
	}
	return map[string]any{
		"diagnostics": []any{
			map[string]any{"key": "goal", "value": input.Goal},
		},
		"escalations":  []any{"Escalate to the consuming repository owner; do not guess a Proofkit route from an unknown goal."},
		"nextCommands": []any{},
		"nonClaims":    mergedNonClaims(input.CallerNonClaims),
		"omitted": []any{
			map[string]any{"reason": "Unknown goals are not routed because that would create an implicit policy owner inside Proofkit."},
		},
		"reportId":            input.RouteID,
		"reportKind":          "proofkit.agent-route",
		"requiredInputs":      []any{},
		"schemaVersion":       2,
		"selectedRouteFamily": string(routeFamilyUnknown),
		"state":               "blocked_unknown_goal",
		"stopConditions":      []any{"Stop before running a Proofkit command until the caller supplies a known goal."},
		"callerNonClaims":     toAnySlice(input.CallerNonClaims),
		"guidanceSlice":       guidanceSliceReport(input.Goal, spec),
		"summary": map[string]any{
			"browserMode":         input.BrowserMode,
			"availableInputCount": len(input.AvailableInputs),
			"callerNonClaimCount": len(input.CallerNonClaims),
			"goal":                input.Goal,
			"knownChangedPaths":   len(input.KnownChangedPaths),
			"mode":                input.Mode,
			"observedReportCount": len(input.ObservedReports),
			"openBrowser":         input.OpenBrowser,
		},
	}
}

func buildReport(input routeInput, spec routeSpec, state string, missing []map[string]any) map[string]any {
	nextCommands := commandReports(spec.NextCommands, input)
	if state != "routed" {
		nextCommands = []any{}
	}
	return map[string]any{
		"diagnostics":         diagnostics(input, state, missing),
		"escalations":         toAnySlice(spec.Escalations),
		"nextCommands":        nextCommands,
		"nonClaims":           mergedNonClaims(input.CallerNonClaims),
		"omitted":             omittedReports(spec.NextCommands, input.AvailableInputs),
		"observedReports":     observedReportReports(input.ObservedReports),
		"reportId":            input.RouteID,
		"reportKind":          "proofkit.agent-route",
		"requiredInputs":      requiredInputReports(missing),
		"schemaVersion":       2,
		"selectedRouteFamily": string(spec.RouteFamily),
		"state":               state,
		"stopConditions":      toAnySlice(spec.StopConditions),
		"callerNonClaims":     toAnySlice(input.CallerNonClaims),
		"guidanceSlice":       guidanceSliceReport(input.Goal, spec),
		"summary": map[string]any{
			"browserMode":         input.BrowserMode,
			"availableInputCount": len(input.AvailableInputs),
			"callerNonClaimCount": len(input.CallerNonClaims),
			"goal":                input.Goal,
			"knownChangedPaths":   len(input.KnownChangedPaths),
			"mode":                input.Mode,
			"observedReportCount": len(input.ObservedReports),
			"openBrowser":         input.OpenBrowser,
		},
	}
}

func commandReports(commands []commandSpec, input routeInput) []any {
	result := []any{}
	for _, command := range commands {
		if !commandInputsAvailable(command, input.AvailableInputs) {
			continue
		}
		argv := []any{"agentic-proofkit", command.Command}
		for _, arg := range command.ExtraArgs {
			argv = append(argv, arg)
		}
		for _, arg := range command.ArgInputs {
			ref, ok := input.AvailableInputs[arg.InputKind]
			if !ok {
				continue
			}
			argv = append(argv, arg.Flag, ref)
		}
		if command.Command == "requirement-browser-server" && input.BrowserMode == "serve_local_view" {
			argv = append(argv, "--serve")
			if input.OpenBrowser {
				argv = append(argv, "--open")
			}
		}
		if command.InputKind != "" {
			ref, ok := input.AvailableInputs[command.InputKind]
			if !ok {
				continue
			}
			argv = append(argv, "--input", ref)
		}
		report := map[string]any{
			"argv":    argv,
			"command": command.Command,
			"why":     command.Why,
		}
		if browserMode := browserModeForCommand(command, input); browserMode != nil {
			report["browserMode"] = browserMode
		}
		result = append(result, report)
	}
	return result
}

func commandInputsAvailable(command commandSpec, available map[string]string) bool {
	if command.InputKind != "" {
		if _, ok := available[command.InputKind]; !ok {
			return false
		}
	}
	for _, arg := range command.ArgInputs {
		if _, ok := available[arg.InputKind]; !ok {
			return false
		}
	}
	return true
}

func browserModeForCommand(command commandSpec, input routeInput) any {
	if command.Command != "requirement-browser-server" {
		return nil
	}
	return input.BrowserMode
}

func omittedReports(commands []commandSpec, available map[string]string) []any {
	result := []any{}
	for _, command := range commands {
		if commandInputsAvailable(command, available) {
			continue
		}
		missing := command.InputKind
		if missing == "" || hasInputKind(available, missing) {
			for _, arg := range command.ArgInputs {
				if !hasInputKind(available, arg.InputKind) {
					missing = arg.InputKind
					break
				}
			}
		}
		result = append(result, map[string]any{
			"command":            command.Command,
			"missingInputKind":   missing,
			"reason":             omittedReason(command),
			"safePlaceholderUse": false,
		})
	}
	return result
}

func hasInputKind(available map[string]string, kind string) bool {
	_, ok := available[kind]
	return ok
}

func omittedReason(command commandSpec) string {
	if command.Command == "selective-gate-obligation-decision-input" {
		return "Command is not emitted because it requires a caller-owned obligation_decision_input composed from the selective-gate-evidence output plus command routes, currentness, and trust facts."
	}
	return "Command is not emitted because the caller did not provide its required input ref."
}

func diagnostics(input routeInput, state string, missing []map[string]any) []any {
	values := []any{
		map[string]any{"key": "goal", "value": input.Goal},
		map[string]any{"key": "mode", "value": input.Mode},
		map[string]any{"key": "state", "value": state},
	}
	if len(missing) > 0 {
		values = append(values, map[string]any{"key": "missingRequiredInputCount", "value": len(missing)})
	}
	blockingReports := blockingObservedReports(input.ObservedReports)
	if len(blockingReports) > 0 {
		values = append(values, map[string]any{"key": "blockingObservedReportCount", "value": len(blockingReports)})
	}
	return values
}

func requiredInputReports(missing []map[string]any) []any {
	result := make([]any, 0, len(missing))
	for _, value := range missing {
		result = append(result, value)
	}
	return result
}

func sortedKeys(values map[string]struct{}) []any {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]any, 0, len(keys))
	for _, key := range keys {
		result = append(result, key)
	}
	return result
}

func toAnySlice(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func mergedNonClaims(caller []string) []any {
	return toAnySlice(sortedUniqueStrings(append(append([]string{}, anyStrings(nonClaims)...), caller...)))
}

func anyStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func blockingObservedReports(reports []observedReport) []observedReport {
	blocked := []observedReport{}
	for _, item := range reports {
		if item.State != "passed" {
			blocked = append(blocked, item)
		}
	}
	return blocked
}

func observedReportReports(reports []observedReport) []any {
	result := make([]any, 0, len(reports))
	for _, item := range reports {
		result = append(result, map[string]any{
			"kind":  item.Kind,
			"ref":   item.Ref,
			"state": item.State,
		})
	}
	return result
}

func guidanceSliceReport(goal string, spec routeSpec) map[string]any {
	return map[string]any{
		"authorityRefs": []any{
			map[string]any{
				"path":     "docs/proofkit-contract-map.md",
				"reason":   "Maintained routing surface for command-family decisions.",
				"refId":    "proofkit.agent-route.contract-map",
				"role":     "router",
				"selector": "Agent Decision Procedure",
			},
			map[string]any{
				"path":     "proofkit/cli-contract.v2.json",
				"reason":   "Machine-readable CLI command and flag contract.",
				"refId":    "proofkit.agent-route.cli-contract",
				"role":     "command_registry",
				"selector": "commands",
			},
			map[string]any{
				"path":     "NON_CLAIMS.md",
				"reason":   "Boundary denials for agent guidance and derived reports.",
				"refId":    "proofkit.agent-route.non-claims",
				"role":     "non_claim_boundary",
				"selector": "agent guidance envelopes",
			},
		},
		"routeFamily":     string(spec.RouteFamily),
		"lookupOnly":      true,
		"nonClaims":       toAnySlice(spec.SliceNonClaims),
		"sliceId":         "proofkit.agent-route.slice." + strings.ReplaceAll(goal, "_", "-"),
		"sliceSummary":    spec.SliceSummary,
		"sourceAuthority": "derived_from_maintained_owner_surfaces",
	}
}

func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value == "" {
			continue
		}
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
