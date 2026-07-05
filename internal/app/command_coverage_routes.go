package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type commandCoverageRoute struct {
	file          string
	kind          string
	rationale     string
	semanticProof commandCoverageSemanticProof
	testName      string
}

type commandCoverageSemanticProof struct {
	ref string
}

type CommandCoverageSummary struct {
	Command            string
	CommandRef         string
	RouteCount         int
	SemanticRouteCount int
	RouteSmokeCount    int
}

var requiredInputAdmissionRoute = commandCoverageRoute{
	file:      "internal/app/command_coverage_test.go",
	kind:      "routing_admission_smoke_nonclaim",
	rationale: "The command-specific CLI route must read caller input and fail closed for malformed records.",
	testName:  "TestRequiredInputCommandsRejectMalformedCallerRecords",
}

var commandCoverageRoutes = map[string][]commandCoverageRoute{
	"adoption-checklist":         {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/adoptionchecklist/adoptionchecklist_test.go", "TestBuildClassifiesRequiredChecklistItemsAndPreservesOptionalNonFailures", semanticRouteProof("adoptionchecklist.build_classifies_required_checklist_items_and_preserves_optional_non_failures"), "Adoption checklist reports must fail missing, blocked, and not-applicable required items while preserving optional non-failures.")},
	"adoption-contract-envelope": {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/adoptioncontract/adoptioncontract_test.go", "TestBuildDelegatesModesWithParity", semanticRouteProof("adoptioncontract.build_delegates_modes_with_parity"), "Adoption contract envelope admission must prove aggregate-root admission while delegating selected modes to existing child command outputs without drift.")},
	"adoption-doctor":            {requiredInputAdmissionRoute, directCLIRoute("internal/app/cli_abi_test.go", "TestAdoptionDoctorCLIABI", semanticRouteProof("cli_abi.adoption_doctor_cliabi"), "Adoption doctor CLI ABI must emit stable report and agent-envelope JSON for admitted caller records."), packageFalsifierRoute("internal/command/adoptiondoctor/adoptiondoctor_test.go", "TestBuildFailsEnforcementForCandidateBoundaryAndMissingRoutes", semanticRouteProof("adoptiondoctor.build_fails_enforcement_for_candidate_boundary_and_missing_routes"), "Adoption doctor reports must fail closed for enforcement modes when caller-provided owner routes or candidate boundaries are not admitted.")},
	"adoption-workflow-plan":     {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/adoptionworkflow/adoptionworkflow_test.go", "TestBuildGeneratesBoundedCommandArgv", semanticRouteProof("adoptionworkflow.build_generates_bounded_command_argv"), "Adoption workflow plans must generate bounded argv commands from admitted route refs.")},
	"agent-route":                {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/agentroute/agentroute_test.go", "TestBuildRoutesRequirementSourceAndBlocksUnknownGoal", semanticRouteProof("agentroute.build_routes_requirement_source_and_blocks_unknown_goal"), "Agent route reports must select a deterministic command family from explicit caller-owned input and fail closed for unknown goals."), packageFalsifierRoute("internal/command/agentroute/agentroute_test.go", "TestBuildEnvelopeKeepsBlockedRoutesAsStopSignals", semanticRouteProof("agentroute.build_envelope_keeps_blocked_routes_as_stop_signals"), "Agent route envelopes must preserve missing-input route states as stop signals instead of executable guidance."), packageFalsifierRoute("internal/command/agentroute/agentroute_test.go", "TestBuildEnvelopeCarriesBlockedObservedReportPreconditions", semanticRouteProof("agentroute.build_envelope_carries_blocked_observed_report_preconditions"), "Agent route envelopes must preserve non-passed observed reports as blocked preconditions instead of executable guidance.")},
	"binding-partition":          {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/bindingpartition/bindingpartition_test.go", "TestBuildRejectsCrossSurfaceRouteReferenceWithoutDelegation", semanticRouteProof("bindingpartition.build_rejects_cross_surface_route_reference_without_delegation"), "Binding partition admission must reject undelegated cross-surface proof route references.")},
	"branch-authority":           {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/branchauthority/branchauthority_test.go", "TestBuildAdmitsAlignedRequiredBranchAndRejectsRequiredDrift", semanticRouteProof("branchauthority.build_admits_aligned_required_branch_and_rejects_required_drift"), "Branch authority must reject required branch drift.")},
	"capability-map-admission":   {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/capabilitymapadmission/capability_map_admission_test.go", "TestBuildCodeBaselineFailsMissingCandidateRequirementAndAnchor", semanticRouteProof("capabilitymapadmission.build_code_baseline_rejects_missing_candidate_or_anchor"), "Capability map admission must fail code_baseline mode when candidate requirement ids or active scenario anchors are missing, while keeping outputs candidate-only.")},
	"changed-path-set":           {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/changedpathset/changedpathset_test.go", "TestBuildDeduplicatesAndFailsClosedOnInvalidPaths", semanticRouteProof("changedpathset.build_deduplicates_and_fails_closed_on_invalid_paths"), "Changed path set must deduplicate caller path sources and fail closed with redacted invalid-path diagnostics.")},
	"completion-criteria":        {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/completioncriteria/completioncriteria_test.go", "TestBuildBlocksUnsatisfiedBlockingCriterion", semanticRouteProof("completioncriteria.build_blocks_unsatisfied_blocking_criterion"), "Completion criteria must fail when a blocking criterion is not satisfied.")},
	"conformance-profile": {
		requiredInputAdmissionRoute,
		packageFalsifierRoute("internal/command/conformanceprofile/conformanceprofile_test.go", "TestBuildProfileResolvesRequiredSurfaceAndRejectsMissingSurface", semanticRouteProof("conformanceprofile.build_profile_resolves_required_surface_and_rejects_missing_surface"), "Conformance profile resolution must reject required surfaces absent from the proof contract."),
		packageFalsifierRoute("internal/command/conformanceprofile/conformanceprofile_test.go", "TestBuildVerificationRejectsDuplicateProfiles", semanticRouteProof("conformanceprofile.build_verification_rejects_duplicate_profiles"), "Conformance profile verification must reject duplicate profile identities."),
		packageFalsifierRoute("internal/command/conformanceprofile/conformanceprofile_test.go", "TestListReturnsSortedProfileIDsAndRejectsInvalidInput", semanticRouteProof("conformanceprofile.list_returns_sorted_profile_ids_and_rejects_invalid_input"), "Conformance profile listing must preserve deterministic public ids and reject invalid input."),
	},
	"custom-rule-boundary":                  {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/customruleboundary/customruleboundary_test.go", "TestBuildAdmitsBoundedCustomRuleAndRejectsUnsafeEffects", semanticRouteProof("customruleboundary.build_admits_bounded_custom_rule_and_rejects_unsafe_effects"), "Custom-rule boundary reports must reject unsafe custom-rule effects while keeping custom rules local and non-authoritative.")},
	"deployment-evidence-admission":         {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/deploymentevidenceadmission/deployment_evidence_admission_test.go", "TestBuildAdmitsCandidateEvidenceAndRejectsUnpinnedImages", semanticRouteProof("deployment_evidence_admission.build_admits_candidate_evidence_and_rejects_unpinned_images"), "Deployment evidence admission must reject unpinned image references while admitting explicit candidate evidence.")},
	"document-lifecycle-boundary":           {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/documentlifecycle/documentlifecycle_test.go", "TestBuildAdmitsCurrentDurableDocumentAndRejectsAuthorityDrift", semanticRouteProof("documentlifecycle.build_admits_current_durable_document_and_rejects_authority_drift"), "Document lifecycle boundary reports must reject active authority drift across current, generated, rendered, temporary, and archived surfaces.")},
	"evidence-graph":                        {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementbinding/projections_test.go", "TestBuildEvidenceGraphBuildsGraphAndRejectsFailedReport", semanticRouteProof("projections.build_evidence_graph_builds_graph_and_rejects_failed_report"), "Evidence graph projection must emit graph output only from passed requirement bindings.")},
	"external-consumer":                     {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/externalconsumer/externalconsumer_test.go", "TestBuildAdmitsExternalConsumerProofAndRejectsWorkspaceLock", semanticRouteProof("externalconsumer.build_admits_external_consumer_proof_and_rejects_workspace_lock"), "External consumer evidence must reject lockfiles that resolve through the local workspace.")},
	"gradual-adoption":                      {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/gradualadoption/gradualadoption_test.go", "TestBuildRejectsRollbackShellControlCommand", semanticRouteProof("gradualadoption.build_rejects_rollback_shell_control_command"), "Gradual adoption reports must reject shell-control rollback commands.")},
	"gradual-adoption-bootstrap":            {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/gradualadoption/gradualadoption_test.go", "TestBootstrapRejectsUnknownRootAndNestedFields", semanticRouteProof("gradualadoption.bootstrap_rejects_unknown_root_and_nested_fields"), "Gradual adoption bootstrap must reject unknown root and nested input fields.")},
	"gradual-adoption-guidance":             {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/gradualadoption/guidance_test.go", "TestGuidanceEnforcementFailsClosedForCandidateBoundaries", semanticRouteProof("guidance.guidance_enforcement_fails_closed_for_candidate_boundaries"), "Gradual adoption guidance must fail closed for candidate boundaries in enforcement modes.")},
	"help":                                  {directCLIRoute("internal/app/cli_contract_test.go", "TestHelpCommandContractForms", semanticRouteProof("cli_contract.help_command_contract_forms"), "Help command forms must emit the documented usage contract.")},
	"impact":                                {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/impact/impact_test.go", "TestBuildRoutesChangedRecordToObligationAndRejectsUnboundProofChange", semanticRouteProof("impact.build_routes_changed_record_to_obligation_and_rejects_unbound_proof_change"), "Impact analysis must route changed requirement records to obligations and reject unbound proof-like changes.")},
	"json-report-cli-adapter-source":        {packageFalsifierRoute("internal/command/jsonreportcliadaptersource/json_report_cli_adapter_source_test.go", "TestGeneratedTypeScriptAdapterExecutesCoreSemantics", semanticRouteProof("json_report_cli_adapter_source.generated_type_script_adapter_executes_core_semantics"), "JSON report CLI adapter source generation must emit executable TypeScript that preserves parser, stable JSON, subprocess exit-code, stdout, stderr, and redacted direct-main semantics.")},
	"migration-parity-admission":            {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/migrationparityadmission/migrationparityadmission_test.go", "TestBuildAdmitsMatchedParityAndRejectsDigestDrift", semanticRouteProof("migrationparityadmission.build_admits_matched_parity_and_rejects_digest_drift"), "Migration parity admission must reject matched parity records with digest drift.")},
	"migration-plan":                        {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/migrationplan/migrationplan_test.go", "TestSortedFollowUpCommandsRejectsShellControlTokens", semanticRouteProof("migrationplan.sorted_follow_up_commands_rejects_shell_control_tokens"), "Migration plans must reject shell-control follow-up commands.")},
	"obligation-decision":                   {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/obligationdecision/obligationdecision_test.go", "TestBuildAdmitsSatisfiedBlockingObligationsAndRejectsMissingReceipt", semanticRouteProof("obligationdecision.build_admits_satisfied_blocking_obligations_and_rejects_missing_receipt"), "Obligation decision must fail blocking obligations that lack satisfying evidence states.")},
	"package-runtime-dependency-admission":  {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/packageruntimedependency/package_runtime_dependency_test.go", "TestBuildAdmitsExternalRuntimeDependencyAndRejectsWorkspaceResolution", semanticRouteProof("package_runtime_dependency.build_admits_external_runtime_dependency_and_rejects_workspace_resolution"), "Package runtime dependency admission must reject local workspace resolution.")},
	"pilot-admission":                       {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/pilotadmission/pilotadmission_test.go", "TestBuildRejectsUnknownPilotContractField", semanticRouteProof("pilotadmission.build_rejects_unknown_pilot_contract_field"), "Pilot admission must reject malformed pilot contract records instead of silently accepting unknown policy fields.")},
	"producer-policy-self-proof":            {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/producerpolicyselfproof/producerpolicyselfproof_test.go", "TestBuildRejectsPolicyChangeProvedByNewlyAdmittedProducerTuple", semanticRouteProof("producerpolicyselfproof.build_rejects_policy_change_proved_by_newly_admitted_producer_tuple"), "Producer policy self-proof must reject merge evidence from the producer tuple admitted by the same policy change.")},
	"proof-obligation-algebra":              {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/proofobligationalgebra/proof_obligation_algebra_test.go", "TestBuildAdmitsAtomicObligationAndRejectsMissingRoute", semanticRouteProof("proof_obligation_algebra.build_admits_atomic_obligation_and_rejects_missing_route"), "Proof obligation algebra must reject atomic obligations with no proof route.")},
	"proof-receipt-admission":               {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/proofreceiptadmission/proofreceiptadmission_test.go", "TestBuildAdmitsAdvisoryReceiptAndRejectsMergeSatisfyingWithoutProvenance", semanticRouteProof("proofreceiptadmission.build_admits_advisory_receipt_and_rejects_merge_satisfying_without_provenance"), "Proof receipt admission must reject merge-satisfying receipt class without provenance evidence.")},
	"proof-slice":                           {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementbinding/projections_test.go", "TestBuildProofSliceSelectsRequirementsAndRejectsFailedReport", semanticRouteProof("projections.build_proof_slice_selects_requirements_and_rejects_failed_report"), "Proof slice projection must select scoped requirements and reject failed requirement bindings.")},
	"readiness-closeout":                    {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/readinesscloseout/readinesscloseout_test.go", "TestBuildRejectsBroadNegationAndFrontierOverclaim", semanticRouteProof("readinesscloseout.build_rejects_broad_negation_and_frontier_overclaim"), "Readiness closeout must reject broad negation suppressors and still detect frontier overclaim grammar.")},
	"receipt-currentness-scope":             {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/receiptcurrentnessscope/receipt_currentness_scope_test.go", "TestBuildAdmitsCurrentScopedReceiptAndRejectsStaleDigest", semanticRouteProof("receipt_currentness_scope.build_admits_current_scoped_receipt_and_rejects_stale_digest"), "Receipt currentness-scope admission must reject stale recorded/current digest pairs.")},
	"receipt-producer-admission":            {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/receiptproduceradmission/receiptproduceradmission_test.go", "TestBuildRejectsAdvisoryProducerForMergeSatisfyingReceipt", semanticRouteProof("receiptproduceradmission.build_rejects_advisory_producer_for_merge_satisfying_receipt"), "Receipt producer admission must reject advisory producers for merge-satisfying receipt claims.")},
	"receipt-trust-class":                   {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/receipttrustclass/receipt_trust_class_test.go", "TestBuildAdmitsTrustedReceiptAndRejectsMissingProvenance", semanticRouteProof("receipt_trust_class.build_admits_trusted_receipt_and_rejects_missing_provenance"), "Receipt trust-class admission must reject missing provenance for trust classes that require it.")},
	"registry-consumer":                     {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/registryconsumer/registryconsumer_test.go", "TestRegistryConsumerAcceptsRegistryReleaseProof", semanticRouteProof("registryconsumer.registry_consumer_accepts_registry_release_proof"), "Registry consumer reports must accept registry-release proof only when release authority, registry pack facts, lockfiles, smoke output, and release-authority digest all align."), packageFalsifierRoute("internal/command/registryconsumer/registryconsumer_test.go", "TestRegistryConsumerRejectsLegacyRootImportProof", semanticRouteProof("registryconsumer.registry_consumer_rejects_legacy_root_import_proof"), "Registry consumer reports must reject legacy root import proof shape.")},
	"registry-consumer-proof-input-compose": {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/registryconsumerinputcompose/registry_consumer_input_compose_test.go", "TestBuildComposesInputAcceptedByRegistryConsumer", semanticRouteProof("registry_consumer_input_compose.build_composes_input_accepted_by_registry_consumer"), "Registry consumer proof input composition must project explicit primitive registry and toolchain facts into an input accepted by the existing registry-consumer validator without executing registry or toolchain work."), packageFalsifierRoute("internal/command/registryconsumerinputcompose/registry_consumer_input_compose_test.go", "TestBuildBlocksUnavailableRequiredPreconditionsWithoutAcceptedInput", semanticRouteProof("registry_consumer_input_compose.build_blocks_unavailable_required_preconditions_without_accepted_input"), "Unavailable registry, install, smoke, or rollback preconditions must produce blocked composition output instead of accepted registry-consumer input.")},
	"release-authority":                     {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/releaseauthority/releaseauthority_test.go", "TestBuildRejectsPrivateSourceNPMProvenanceClaim", semanticRouteProof("releaseauthority.build_rejects_private_source_npmprovenance_claim"), "Release authority must reject npm provenance claims without public source repository proof.")},
	"rendered-artifact-freshness":           {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/renderedartifactfreshness/rendered_artifact_freshness_test.go", "TestBuildAdmitsFreshRenderedArtifactAndRejectsDigestDrift", semanticRouteProof("rendered_artifact_freshness.build_admits_fresh_rendered_artifact_and_rejects_digest_drift"), "Rendered artifact freshness must reject recorded/current digest drift.")},
	"repo-profile-admission":                {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/repoprofileadmission/repo_profile_admission_test.go", "TestBuildAdmitsValidRepoProfileAndRejectsRootPackageMismatch", semanticRouteProof("repo_profile_admission.build_admits_valid_repo_profile_and_rejects_root_package_mismatch"), "Repo profile admission must reject mismatch between profile root package and observed package facts.")},
	"requirement-bindings":                  {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementbinding/projections_test.go", "TestBuildReportFailsUnknownRequirementBinding", semanticRouteProof("projections.build_report_fails_unknown_requirement_binding"), "Requirement binding reports must fail closed when bindings reference unknown requirements.")},
	"requirement-browser-server":            {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementbrowser/server_test.go", "TestStartServerFailsClosedForNonLoopbackHosts", semanticRouteProof("server.start_server_fails_closed_for_non_loopback_hosts"), "Requirement browser server must reject non-loopback host binding."), directCLIRoute("internal/app/cli_abi_test.go", "TestRequirementBrowserServerSpecTreeCLIABI", semanticRouteProof("cli_abi.requirement_browser_server_spec_tree_cliabi"), "Requirement browser server CLI ABI must admit explicit spec-tree view routing and emit a presentation-only browser plan.")},
	"requirement-coverage-input-compose": {
		requiredInputAdmissionRoute,
		packageFalsifierRoute("internal/command/requirementcoverageinput/requirementcoverageinput_test.go", "TestBuildComposesInputPreservesDeclaredUniverseAndAllowsDownstreamFailures", semanticRouteProof("requirementcoverageinput.build_composes_input_preserves_declared_universe_and_allows_downstream_failures"), "Requirement coverage input composition must preserve declared universe facts while keeping downstream coverage failures separate from composition admission."),
		packageFalsifierRoute("internal/command/requirementcoverageinput/requirementcoverageinput_test.go", "TestBuildRejectsFabricatedDirectEnvelopeWithSourceMetadata", semanticRouteProof("requirementcoverageinput.build_rejects_fabricated_direct_envelope_with_source_metadata"), "Requirement coverage input composition must reject fabricated normalized inventory envelopes before composing a coverage view input."),
		packageFalsifierRoute("internal/command/requirementcoverageinput/requirementcoverageinput_test.go", "TestBuildComposesDirectRequirementProofBindingAndInventory", semanticRouteProof("requirementcoverageinput.build_composes_direct_requirement_proof_binding_and_inventory"), "Requirement coverage input composition must admit direct proof-binding and test-inventory child reports before composing the coverage-view input."),
	},
	"requirement-coverage-view":                {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementcoverageview/requirementcoverageview_test.go", "TestBuildJSONRejectsRouteOnlyCoverageForBlockingRequirement", semanticRouteProof("requirementcoverageview.build_jsonrejects_route_only_coverage_for_blocking_requirement"), "Requirement coverage views must not treat route-only smoke evidence as semantic requirement coverage.")},
	"requirement-impact-input-compose":         {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementimpactinput/requirementimpactinput_test.go", "TestBuildComposesInputAndRoutesChangedBlockingRequirement", semanticRouteProof("requirementimpactinput.build_composes_input_and_routes_changed_blocking_requirement"), "Requirement impact input composition must emit direct impact inputs from admitted caller-owned sources while preserving downstream impact semantics.")},
	"requirement-proof-resolver":               {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementbinding/compact_contract_test.go", "TestBuildResolverRejectsUnscopedCompactIdentity", semanticRouteProof("compact_contract.build_resolver_rejects_unscoped_compact_identity"), "Requirement proof resolver must fail closed on unscoped scenario ids and unadmitted witness selector identities."), packageFalsifierRoute("internal/command/requirementbinding/compact_contract_test.go", "TestBuildResolverEmitsNamedLookupFacts", semanticRouteProof("compact_contract.build_resolver_emits_named_lookup_facts"), "Requirement proof resolver must emit deterministic named lookup facts for commands, environment classes, surfaces, scenarios, and witness selectors.")},
	"requirement-proof-source-set":             {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementproofsourceset/requirementproofsourceset_test.go", "TestBuildSelectsSourceSetRowsAndEmitsResolverInput", semanticRouteProof("requirementproofsourceset.build_selects_source_set_rows_and_emits_resolver_input"), "Requirement proof source-set normalization must select caller-owned source rows and emit resolver-compatible projections without scanning repositories.")},
	"requirement-proof-view":                   {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementproofview/requirementproofview_test.go", "TestBuildMarkdownEscapesCallerControlledCompactFields", semanticRouteProof("requirementproofview.build_markdown_escapes_caller_controlled_compact_fields"), "Requirement proof view must escape caller-controlled compact binding fields.")},
	"requirement-authoring-plan":               {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementauthoringplan/requirement_authoring_plan_test.go", "TestBuildRejectsCandidateSourceAdmissionFailure", semanticRouteProof("requirement_authoring_plan.build_rejects_candidate_source_admission_failure"), "Requirement authoring plans must keep candidate source previews candidate-only and fail closed when the composed source cannot pass requirement-source admission.")},
	"requirement-source-admission":             {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementsourceadmission/requirementsourceadmission_test.go", "TestEvaluateRejectsBlockingRequirementWithoutProofRoute", semanticRouteProof("requirementsourceadmission.evaluate_rejects_blocking_requirement_without_proof_route"), "Requirement source admission must reject blocking active requirements without proof binding routes.")},
	"requirement-source-transition":            {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementsourcetransition/requirementsourcetransition_test.go", "TestBuildRejectsRequirementSourceTransitionContractViolations", semanticRouteProof("requirementsourcetransition.build_rejects_requirement_source_transition_contract_violations"), "Requirement source transition must reject previous and next source admission, source identity, package boundary, durable identity, terminal state, evidence-delta, active replacement, and stable-ref contract violations.")},
	"requirement-source-view":                  {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementsourceview/requirementsourceview_test.go", "TestBuildMarkdownEscapesCallerControlledText", semanticRouteProof("requirementsourceview.build_markdown_escapes_caller_controlled_text"), "Requirement source view must escape caller-controlled requirement text.")},
	"requirement-spec-tree":                    {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementspectree/requirementspectree_test.go", "TestBuildRejectsDAGAndStaleDigest", semanticRouteProof("requirementspectree.build_rejects_dagand_stale_digest"), "Requirement spec tree admission must reject DAG topology and stale caller-provided source digest facts.")},
	"requirement-spec-tree-view":               {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/requirementspectree/requirementspectree_test.go", "TestBuildViewMarkdownAndHTMLAreDeterministicAndEscaped", semanticRouteProof("requirementspectree.build_view_markdown_and_htmlare_deterministic_and_escaped"), "Requirement spec tree views must reuse admitted spec-tree input and escape caller-controlled text in deterministic HTML and Markdown projections.")},
	"scaffold-profile-plan":                    {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/scaffoldprofileplan/scaffoldprofileplan_test.go", "TestBuildAcceptsCommandMatcherHints", semanticRouteProof("scaffoldprofileplan.build_accepts_command_matcher_hints"), "Scaffold profile planning must preserve caller-reviewed command matcher hints as deterministic profile draft data.")},
	"scaffold-project-structure":               {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/projectstructure/projectstructure_test.go", "TestBuildAdmitsProjectStructureScaffoldAndEmitsBoundedEnvelope", semanticRouteProof("projectstructure.build_admits_project_structure_scaffold_and_emits_bounded_envelope"), "Project structure scaffold must emit deterministic source-report identity and bounded agent guidance without writing files."), packageFalsifierRoute("internal/command/projectstructure/projectstructure_test.go", "TestBuildRejectsProjectStructurePathDriftAndUnsafePaths", semanticRouteProof("projectstructure.build_rejects_project_structure_path_drift_and_unsafe_paths"), "Project structure scaffold must reject unsafe paths and inconsistent bootstrap/profile proof paths.")},
	"selective-gate-evidence":                  {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/selectivegateevidence/selectivegateevidence_test.go", "TestBuildRejectsMergeSatisfyingEvidenceWithoutProducerAdmission", semanticRouteProof("selectivegateevidence.build_rejects_merge_satisfying_evidence_without_producer_admission"), "Selective gate evidence must reject merge-satisfying evidence without producer admission."), packageFalsifierRoute("internal/command/selectivegateevidence/selectivegateevidence_test.go", "TestBuildReportsMergeEvidenceWithoutApprovingMerge", semanticRouteProof("selectivegateevidence.build_reports_merge_evidence_without_approving_merge"), "Selective gate evidence must report merge evidence facts without approving consumer-owned merge admission.")},
	"selective-gate-obligation-decision-input": {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/selectivegateevidence/selectivegateevidence_test.go", "TestProjectObligationDecisionBuildsInputAndRejectsUnroutedCommand", semanticRouteProof("selectivegateevidence.project_obligation_decision_builds_input_and_rejects_unrouted_command"), "Selective evidence projection must reject receipts that cannot be routed to planned commands.")},
	"selective-gate-plan":                      {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/selectivegateplan/selectivegateplan_test.go", "TestBuildFailsClosedForUncoveredUnknownEdge", semanticRouteProof("selectivegateplan.build_fails_closed_for_uncovered_unknown_edge"), "Selective gate planning must fail closed for uncovered unknown dependency edges.")},
	"self-check":                               {directCLIRoute("internal/app/app_test.go", "TestSelfCheckRejectsDuplicateKeys", semanticRouteProof("app.self_check_rejects_duplicate_keys"), "Self-check must reject ambiguous duplicate-key JSON without echoing the duplicated key.")},
	"spec-overview-claims":                     {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/specoverviewclaims/specoverviewclaims_test.go", "TestBuildRejectsInvalidOverviewClaimBoundaryFacts", semanticRouteProof("specoverviewclaims.build_rejects_invalid_overview_claim_boundary_facts"), "Spec overview claim admission must reject invalid path, extraction, digest, marker, rationale, and non-claim boundary facts."), packageFalsifierRoute("internal/command/specoverviewclaims/specoverviewclaims_test.go", "TestBuildRejectsNonDurableRequirementCitationsForEveryNonDurableKind", semanticRouteProof("specoverviewclaims.build_rejects_non_durable_requirement_citations_for_every_non_durable_kind"), "Spec overview claim admission must reject every non-durable claim kind when it carries requirement citations.")},
	"spec-proof-bundle-admission":              {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/specproofbundleadmission/specproofbundleadmission_test.go", "TestBuildRejectsForgedReceiptAdmissionChild", semanticRouteProof("specproofbundleadmission.build_rejects_forged_receipt_admission_child"), "Spec proof bundle admission must reject forged child receipt admission reports.")},
	"stack-preset":                             {directCLIRoute("internal/app/command_coverage_test.go", "TestNoInputCommandsHaveCommandSpecificBehavior", semanticRouteProof("command_coverage.no_input_commands_have_command_specific_behavior"), "Stack preset CLI route must emit JSON and reject unknown preset flags."), packageFalsifierRoute("internal/command/stackpreset/stackpreset_test.go", "TestPresetInventoryIsCompleteDeterministicAndDefensivelyCopied", semanticRouteProof("stackpreset.preset_inventory_is_complete_deterministic_and_defensively_copied"), "Stack preset inventory must keep preset ids aligned with complete non-empty profile records and defensive copies."), packageFalsifierRoute("internal/command/stackpreset/stackpreset_test.go", "TestUnknownPresetIsRejected", semanticRouteProof("stackpreset.unknown_preset_is_rejected"), "Stack preset package API must reject unknown preset ids.")},
	"test-evidence-inventory": {
		requiredInputAdmissionRoute,
		packageFalsifierRoute("internal/command/testevidenceinventory/testevidenceinventory_test.go", "TestBuildRejectsWeakOracleAndDuplicateFalsifier", semanticRouteProof("testevidenceinventory.build_rejects_weak_oracle_and_duplicate_falsifier"), "Test evidence inventory must reject weak semantic oracles and duplicate falsifier equivalence claims."),
		packageFalsifierRoute("internal/command/testevidenceinventory/testevidenceinventory_test.go", "TestBuildDiscoveryDraftEmitsCandidateOnlyInventory", semanticRouteProof("testevidenceinventory.build_discovery_draft_emits_candidate_only_inventory"), "Test discovery draft projection must emit candidate-only inventory guidance without closing semantic coverage."),
		packageFalsifierRoute("internal/command/proofbindingtestinventory/proofbindingtestinventory_test.go", "TestBuildRejectsDerivedCommandRefCollision", semanticRouteProof("proofbindingtestinventory.build_rejects_derived_command_ref_collision"), "Proof-binding-derived inventory projection must reject command-ref collisions before emitting normalized inventory."),
	},
	"text-policy":                    {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/textpolicy/textpolicy_test.go", "TestEvaluatePreservesUTF8ASCIIWhitespaceAndBinaryFalsifiers", semanticRouteProof("textpolicy.evaluate_preserves_utf8_asciiwhitespace_and_binary_falsifiers"), "Text policy must preserve UTF-8, ASCII, final-newline, trailing-whitespace, binary-suffix, missing-file, and explicit-inventory falsifiers without scanning repository state.")},
	"typescript-public-api-surfaces": {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/publicapi/public_api_test.go", "TestVerifyTypeScriptPackagePublicAPIRejectsExportStar", semanticRouteProof("public_api.verify_type_script_package_public_apirejects_export_star"), "TypeScript public API verifier must reject export-star surfaces that hide public contract drift."), packageFalsifierRoute("internal/command/publicapi/public_api_test.go", "TestVerifyTypeScriptPackagePublicAPIRejectsExportTargetDifferentFromScannedSource", semanticRouteProof("public_api.verify_type_script_package_public_apirejects_export_target_different_from_scanned_source"), "TypeScript public API verifier must reject export targets that cannot be tied to the scanned source or its compiled target.")},
	"witness-plan":                   {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/witnessplan/witnessplan_test.go", "TestBuildAdmitsSafeCommandAndRejectsShellCommand", semanticRouteProof("witnessplan.build_admits_safe_command_and_rejects_shell_command"), "Witness plan must preserve witness command safety policy and reject shell command execution."), packageFalsifierRoute("internal/command/witnessplan/witnessplan_test.go", "TestBuildProjectsRequirementBindingsToWitnessPlan", semanticRouteProof("witnessplan.build_projects_requirement_bindings_to_witness_plan"), "Witness plan projection must derive witness commands from admitted requirement proof bindings without duplicating command identity.")},
	"witness-scheduler-plan":         {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/witnessschedulerplan/witnessschedulerplan_test.go", "TestBuildRejectsUnsafeParallelWriteCollision", semanticRouteProof("witnessschedulerplan.build_rejects_unsafe_parallel_write_collision"), "Witness scheduler planning must reject unsafe parallel write collisions.")},
	"workspace-changed-package-plan": {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/workspaceplanning/workspaceplanning_test.go", "TestChangedPackagePlanAdmitsPackagesRootAndSchema", semanticRouteProof("workspaceplanning.changed_package_plan_admits_packages_root_and_schema"), "Workspace changed-package planning must admit packagesRoot only through explicit schema-versioned input.")},
	"workspace-manifest-facts":       {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/workspacemanifestfacts/workspace_manifest_facts_test.go", "TestBuildProjectsManifestFactsAndPlanningInputs", semanticRouteProof("workspace_manifest_facts.build_projects_manifest_facts_and_planning_inputs"), "Workspace manifest fact projection must emit registry-compatible facts and workspace planning inputs from explicit caller-owned manifests."), packageFalsifierRoute("internal/command/workspacemanifestfacts/workspace_manifest_facts_test.go", "TestBuildRejectsUnsafeManifestPathAndDuplicatePackageIdentity", semanticRouteProof("workspace_manifest_facts.build_rejects_unsafe_manifest_path_and_duplicate_package_identity"), "Workspace manifest fact projection must reject unsafe paths and duplicate package identities.")},
	"workspace-registry":             {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/workspaceregistry/workspaceregistry_test.go", "TestBuildAdmitsWorkspaceRegistryAndRejectsMissingScriptTarget", semanticRouteProof("workspaceregistry.build_admits_workspace_registry_and_rejects_missing_script_target"), "Workspace registry admission must reject scripts targeting missing workspace packages.")},
	"workspace-shard-partition":      {requiredInputAdmissionRoute, packageFalsifierRoute("internal/command/workspaceplanning/workspaceplanning_test.go", "TestShardPartitionAdmitsCoveredRootsAndRejectsMissingDependency", semanticRouteProof("workspaceplanning.shard_partition_admits_covered_roots_and_rejects_missing_dependency"), "Workspace shard partitioning must reject roots that depend on missing workspace packages.")},
}

func semanticRouteProof(ref string) commandCoverageSemanticProof {
	return commandCoverageSemanticProof{ref: ref}
}

func directCLIRoute(file string, testName string, proof commandCoverageSemanticProof, rationale string) commandCoverageRoute {
	return commandCoverageRoute{
		file:          file,
		kind:          "direct_semantic_falsifier",
		rationale:     rationale,
		semanticProof: proof,
		testName:      testName,
	}
}

func packageFalsifierRoute(file string, testName string, proof commandCoverageSemanticProof, rationale string) commandCoverageRoute {
	return commandCoverageRoute{
		file:          file,
		kind:          "package_level_falsifier",
		rationale:     rationale,
		semanticProof: proof,
		testName:      testName,
	}
}

func CommandCoverageSummaries() []CommandCoverageSummary {
	commands := make([]string, 0, len(supportedCommands))
	for command := range supportedCommands {
		commands = append(commands, command)
	}
	sort.Strings(commands)
	out := make([]CommandCoverageSummary, 0, len(commands))
	for _, command := range commands {
		routes := commandCoverageRoutes[command]
		summary := CommandCoverageSummary{Command: command, CommandRef: CommandCoverageCommandRef(command), RouteCount: len(routes)}
		for _, route := range routes {
			switch route.kind {
			case "direct_semantic_falsifier", "package_level_falsifier":
				summary.SemanticRouteCount++
			case "routing_admission_smoke_nonclaim":
				summary.RouteSmokeCount++
			}
		}
		out = append(out, summary)
	}
	return out
}

func CommandCoverageInventory() (map[string]any, error) {
	return commandCoverageInventoryFrom(commandCoverageRoutes)
}

func commandCoverageInventoryFrom(routes map[string][]commandCoverageRoute) (map[string]any, error) {
	commands := make([]string, 0, len(routes))
	for command := range routes {
		commands = append(commands, command)
	}
	sort.Strings(commands)
	entries := []any{}
	for _, command := range commands {
		for index, route := range routes[command] {
			if problem := route.semanticProofProblem(); problem != "" {
				return nil, fmt.Errorf("%s coverage route %s has invalid semantic proof metadata: %s", command, route.testName, problem)
			}
			if problem := routeSemanticOwnerProblem(command, route); problem != "" {
				return nil, fmt.Errorf("%s coverage route %s has invalid semantic owner scope: %s", command, route.testName, problem)
			}
			entries = append(entries, route.inventoryEntry(command, index))
		}
	}
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"inventoryId":   "proofkit.command_coverage.inventory",
		"authority":     "caller_owned_inventory",
		"ownerId":       "proofkit.command_coverage",
		"sourceId":      "proofkit.command_coverage.routes",
		"entries":       entries,
		"nonClaims": []any{
			"Command coverage inventory does not execute tests.",
			"Command coverage inventory does not prove native command success, receipt freshness, or merge satisfaction.",
			"Routing smoke entries prove CLI input routing only and cannot satisfy semantic command coverage.",
		},
	}, nil
}

func CommandCoverageCommandRef(command string) string {
	return "proofkit.cli." + command
}

func (route commandCoverageRoute) inventoryEntry(command string, index int) map[string]any {
	component := commandCoverageIDComponent(command)
	entry := map[string]any{
		"testId":             fmt.Sprintf("proofkit.command_coverage.%s.route_%d", component, index),
		"selector":           route.file + "::" + route.testName,
		"sourcePath":         route.file,
		"ownerId":            "proofkit.command_coverage",
		"evidenceClass":      route.evidenceClass(),
		"requirementRefs":    []any{},
		"ownerInvariantRefs": []any{},
		"commandRefs":        []any{CommandCoverageCommandRef(command)},
		"witnessRefs":        []any{},
		"falsifier":          nil,
		"oracle":             nil,
		"nonClaims":          route.nonClaims(),
	}
	if route.isSemantic() {
		proof := route.semanticProof
		entry["testId"] = proof.routeTestID()
		entry["ownerInvariantRefs"] = []any{proof.semanticRouteInvariantID()}
		entry["falsifier"] = map[string]any{
			"falsifierId":                proof.falsifierID(),
			"negativeCaseId":             proof.negativeCaseID(),
			"wrongImplementationClassId": proof.wrongImplementationClassID(),
			"dominanceGroup":             proof.dominanceGroup(),
			"supersedes":                 []any{},
		}
		entry["oracle"] = map[string]any{
			"oracleId":         proof.oracleID(),
			"oracleKind":       "semantic_route_falsifier",
			"assertionSummary": route.rationale,
		}
	}
	return entry
}

func (route commandCoverageRoute) isSemantic() bool {
	return route.kind == "direct_semantic_falsifier" || route.kind == "package_level_falsifier"
}

func (route commandCoverageRoute) evidenceClass() string {
	if route.isSemantic() {
		return "semantic_falsifier"
	}
	return "routing_smoke_nonclaim"
}

func (route commandCoverageRoute) nonClaims() []any {
	if route.isSemantic() {
		return []any{"This inventory entry does not execute the referenced test or claim runtime pass evidence."}
	}
	return []any{"This route-only inventory entry is a non-claim for semantic command coverage."}
}

func commandCoverageIDComponent(command string) string {
	return strings.NewReplacer("-", "_", ".", "_", ":", "_", "/", "_").Replace(command)
}

func (route commandCoverageRoute) semanticProofProblem() string {
	if !route.isSemantic() {
		if route.semanticProof.ref != "" {
			return "route-only coverage must not carry semantic proof metadata"
		}
		return ""
	}
	ref := route.semanticProof.ref
	if ref == "" {
		return "semantic coverage route requires owner-declared proof metadata"
	}
	if containsRouteIndexToken(ref) {
		return "semantic proof metadata must not be derived from route index"
	}
	if strings.HasPrefix(ref, ".") || strings.HasSuffix(ref, ".") || strings.Contains(ref, "..") {
		return "semantic proof metadata must be a stable dotted identifier"
	}
	for _, character := range ref {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '.', character == '_', character == '-':
		default:
			return "semantic proof metadata must use lowercase stable identifier characters"
		}
	}
	return ""
}

func routeSemanticOwnerProblem(command string, route commandCoverageRoute) string {
	switch route.kind {
	case "direct_semantic_falsifier":
		if !strings.HasPrefix(route.file, "internal/app/") {
			return "direct semantic routes must point at app-level CLI ABI tests"
		}
		appTests := commandSemanticAppTests(command)
		if !stringSliceContains(appTests, route.testName) {
			return "direct semantic routes for " + command + " must point at " + strings.Join(appTests, " or ")
		}
	case "package_level_falsifier":
		expectedDirs := commandSemanticOwnerDirs(command)
		if len(expectedDirs) == 0 {
			return "package-level semantic routes require an admitted command package owner"
		}
		for _, dir := range expectedDirs {
			if strings.HasPrefix(route.file, "internal/command/"+dir+"/") {
				return ""
			}
		}
		return "package-level semantic routes for " + command + " must point at " + strings.Join(expectedDirs, " or ")
	}
	return ""
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func containsRouteIndexToken(value string) bool {
	offset := 0
	for {
		index := strings.Index(value[offset:], "route_")
		if index < 0 {
			return false
		}
		start := offset + index
		digitIndex := start + len("route_")
		if digitIndex < len(value) && value[digitIndex] >= '0' && value[digitIndex] <= '9' {
			return true
		}
		offset = start + len("route_")
		if offset >= len(value) {
			return false
		}
	}
}

func (proof commandCoverageSemanticProof) baseID() string {
	return "proofkit.command_coverage." + proof.ref
}

func (proof commandCoverageSemanticProof) dominanceGroup() string {
	return proof.baseID()
}

func (proof commandCoverageSemanticProof) falsifierID() string {
	return proof.baseID() + ".falsifier"
}

func (proof commandCoverageSemanticProof) negativeCaseID() string {
	return proof.baseID() + ".negative_fixture"
}

func (proof commandCoverageSemanticProof) oracleID() string {
	return proof.baseID() + ".oracle_assertion"
}

func (proof commandCoverageSemanticProof) routeTestID() string {
	return proof.baseID() + ".route"
}

func (proof commandCoverageSemanticProof) semanticRouteInvariantID() string {
	return proof.baseID() + ".semantic_route"
}

func (proof commandCoverageSemanticProof) wrongImplementationClassID() string {
	return proof.baseID() + ".without_semantic_route"
}
