package main

type inventoryKey struct {
	requirementID string
	scenarioID    string
}

type requiredInventoryEntry struct {
	commandIDs         []string
	environmentClasses []string
	selectors          []string
	witnessPath        string
}

func requiredBindingWitnessInventory() map[inventoryKey]requiredInventoryEntry {
	return map[inventoryKey]requiredInventoryEntry{
		{"REQ-PROOFKIT-WORKFLOW-001", "proofkit.agent-workflow.pure-single-admission-owner"}: {
			witnessPath: "internal/command/changeworkflowplan/change_workflow_plan_test.go",
			selectors:   []string{"TestWorkflowPurityPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-002", "proofkit.agent-workflow.stage-prefix-and-terminal-relation"}: {
			witnessPath: "internal/command/changeworkflowplan/state_test.go",
			selectors:   []string{"TestWorkflowStatePredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-003", "proofkit.agent-workflow.total-checkpoint-successor-relation"}: {
			witnessPath: "internal/command/changeworkflowplan/state_test.go",
			selectors:   []string{"TestWorkflowCheckpointPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-004", "proofkit.agent-workflow.review-identity-closure"}: {
			witnessPath: "internal/command/changeworkflowplan/admission_test.go",
			selectors:   []string{"TestWorkflowIdentityPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-005", "proofkit.agent-workflow.reference-closed-bounded-context"}: {
			witnessPath: "internal/command/changeworkflowplan/context_closure_test.go",
			selectors:   []string{"TestWorkflowClosurePredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-006", "proofkit.agent-workflow.no-ambient-authority"}: {
			witnessPath: "internal/command/changeworkflowplan/dependency_test.go",
			selectors:   []string{"TestWorkflowAmbientAuthorityPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-007", "proofkit.agent-workflow.native-evidence-guidance-purity"}: {
			witnessPath: "internal/command/nativeevidenceguidance/dependency_test.go",
			selectors:   []string{"TestGuidanceNoAmbientDependencyPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-007", "proofkit.agent-workflow.native-evidence-guidance-slot-closure"}: {
			witnessPath: "internal/command/nativeevidenceguidance/guidance_test.go",
			selectors:   []string{"TestGuidanceReferenceIsCompactAndOwnerBound", "TestGuidanceSlotPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-008", "proofkit.agent-workflow.bounded-safe-text"}: {
			witnessPath: "internal/command/changeworkflowplan/text_test.go",
			selectors:   []string{"TestWorkflowTerminalTextIsOperationallyComplete", "TestWorkflowTextPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-008", "proofkit.agent-workflow.prompt-coordinate-and-escalation-closure"}: {
			witnessPath: "internal/command/changeworkflowplan/prompt_test.go",
			selectors:   []string{"TestWorkflowPromptPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-009", "proofkit.agent-workflow.cli-presentation-capability-product"}: {
			witnessPath: "internal/app/agent_workflow_command_test.go",
			selectors:   []string{"TestAgentWorkflowCLITruthTable"},
		},
		{"REQ-PROOFKIT-WORKFLOW-009", "proofkit.agent-workflow.style-strip-parity"}: {
			witnessPath: "internal/command/changeworkflowplan/text_test.go",
			selectors:   []string{"TestWorkflowTextProjectionParity"},
		},
		{"REQ-PROOFKIT-WORKFLOW-010", "proofkit.agent-workflow.catalog-prerequisite-causality"}: {
			witnessPath: "internal/command/changeworkflowplan/state_test.go",
			selectors:   []string{"TestWorkflowStatePredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-010", "proofkit.agent-workflow.semantic-owner-minimality"}: {
			witnessPath: "internal/command/nativeevidenceguidance/guidance_test.go",
			selectors:   []string{"TestGuidancePurityPredicates"},
		},
		{"REQ-PROOFKIT-WORKFLOW-010", "proofkit.agent-workflow.semantic-owner-topology"}: {
			witnessPath: "internal/app/agent_workflow_topology_test.go",
			selectors:   []string{"TestAgentWorkflowSemanticOwnerTopology"},
		},
		{"REQ-PROOFKIT-WORKFLOW-011", "proofkit.agent-workflow.installed-carrier-smoke-closure"}: {
			witnessPath: "internal/tools/workflowsmoke/workflow_smoke_test.go",
			selectors: []string{
				"TestRunProcessCustomOutputLimitsAreExact",
				"TestRunProcessRejectsInvalidCustomOutputLimitsBeforeStart",
				"TestVerifyAcceptsApplicationCLI",
				"TestVerifyRejectsCarrierContractMutations",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-011", "proofkit.agent-workflow.public-cli-relation-closure"}: {
			witnessPath: "internal/app/agent_workflow_command_test.go",
			selectors:   []string{"TestAgentWorkflowCLITruthTable"},
		},
		{"REQ-PROOFKIT-WORKFLOW-011", "proofkit.agent-workflow.version-edge-wire-observation"}: {
			witnessPath: "internal/app/agent_workflow_version_edge_test.go",
			selectors:   []string{"TestAgentWorkflowVersionEdgeClosesPublicWireAdditions"},
		},
		{"REQ-PROOFKIT-WORKFLOW-012", "proofkit.agent-workflow.project-state-total-classification"}: {
			witnessPath: "internal/command/projectstatus/projectstatus_test.go",
			selectors: []string{
				"TestEvaluateTotalStateActionTable",
				"TestOutputAdmissionRejectsUnreachableClosureCombination",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-012", "proofkit.agent-workflow.project-state-child-admission-owner"}: {
			witnessPath: "internal/command/projectstatus/dependency_test.go",
			selectors:   []string{"TestProjectStatusDelegatesChildAdmissionToMaterializationOwner"},
		},
		{"REQ-PROOFKIT-WORKFLOW-012", "proofkit.agent-workflow.project-state-child-owner-delegation"}: {
			witnessPath: "internal/command/adoptionmaterialization/project_closure_test.go",
			selectors: []string{
				"TestAdmitMaterializedProjectRoutesEveryManifestArtifactKindThroughItsOwner",
				"TestMaterializedProjectRecordSnapshotDoesNotAliasCallerInput",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-013", "proofkit.agent-workflow.project-state-bounded-inspection"}: {
			witnessPath: "internal/command/projectstatus/inspect_test.go",
			selectors: []string{
				"TestInspectAttemptRejectsFinalRepositoryRootReplacement",
				"TestInspectClassifiesMaterializedProjectWithoutApplicationWrites",
				"TestInspectCleanupFailureDominatesRetryableSnapshotChange",
				"TestInspectCohortValidationClosesCleanEpochABA",
				"TestInspectDeduplicatesRepeatedIssueCodes",
				"TestInspectFailsClosedOnSymlinksAndBoundsWithoutDisclosure",
				"TestInspectHonorsCancellationAfterFinalControlObservation",
				"TestInspectHonorsCancellationBetweenBoundedReads",
				"TestInspectMapsInvalidControlState",
				"TestInspectMapsRecoverableControlState",
				"TestInspectRejectsAdmittedChildrenWithInvalidCrossRecordClosure",
				"TestInspectRejectsCaseAliasedCanonicalRoute",
				"TestInspectRejectsChangingControlEpochAcrossBothAttempts",
				"TestOutOfBoundManifestIdentityIsAClassificationNotByteIdentity",
				"TestReadProjectFileEnforcesAggregateBoundBeforeRead",
				"TestReadProjectFileRejectsSameByteRouteReplacement",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-013", "proofkit.agent-workflow.project-state-control-file-coherence"}: {
			witnessPath: "internal/kernel/repositorytransaction/control_inspection_test.go",
			selectors: []string{
				"TestInspectControlFileRejectsGrowthAfterRoutePreflight",
				"TestInspectControlFileRejectsSameByteRouteReplacement",
				"TestInspectControlStateHashesSymlinkTargetsWithoutDisclosingThem",
				"TestInspectControlStateRejectsClassificationChangeHiddenByPortableNameIdentity",
				"TestInspectControlStateRejectsPartialControlObservations",
				"TestInspectControlStateUsesPortableObservationFields",
				"TestInspectionLeaseDoesNotResolveAReplacementRoot",
				"TestInspectionLeaseExportsOnlyReadOnlyFileCapability",
				"TestInspectionLeaseFileCannotBeReassertedAsMutable",
				"TestInspectionLeasePinsRootAndExcludesCooperativeWriter",
				"TestInspectionLeaseRejectsControlNamespaceCreatedAfterOpen",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-013", "proofkit.agent-workflow.project-state-application-write-free-topology"}: {
			witnessPath: "internal/command/projectstatus/dependency_test.go",
			selectors:   []string{"TestProjectStatusProductionTopologyForbidsRepositoryMutationCalls"},
		},
		{"REQ-PROOFKIT-WORKFLOW-013", "proofkit.agent-workflow.project-state-exact-route-traversal"}: {
			witnessPath: "internal/kernel/rootpath/exact_test.go",
			selectors:   []string{"TestOpenExactRegularFileRejectsFinalComponentABA", "TestOpenExactRegularFileRejectsParentSymlinkABA"},
		},
		{"REQ-PROOFKIT-WORKFLOW-014", "proofkit.agent-workflow.project-next-action-output-closure"}: {
			witnessPath: "internal/command/projectstatus/projectstatus_test.go",
			selectors: []string{
				"TestEvaluateTotalStateActionTable",
				"TestOutputAdmissionRejectsReidentifiedStateActionMismatch",
				"TestTextProjectionIsBoundedAndSemanticallyDerived",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-015", "proofkit.agent-workflow.project-navigation-installed-carriers"}: {
			commandIDs:         []string{"proofkit.go-test", "proofkit.package-artifact"},
			environmentClasses: []string{"local-go", "local-go-python"},
			witnessPath:        "internal/tools/workflowsmoke/workflow_smoke_test.go",
			selectors:          []string{"TestVerifyAcceptsApplicationCLI", "TestVerifyRejectsCarrierContractMutations"},
		},
		{"REQ-PROOFKIT-WORKFLOW-015", "proofkit.agent-workflow.project-navigation-installed-npm-carrier-closure"}: {
			witnessPath: "internal/tools/packageverify/workflow_carrier_test.go",
			selectors:   []string{"TestInstalledNPMWorkflowCarrierClosure"},
		},
		{"REQ-PROOFKIT-WORKFLOW-015", "proofkit.agent-workflow.project-navigation-installed-wheel-carrier-closure"}: {
			witnessPath: "internal/tools/pythonpackage/workflow_carrier_test.go",
			selectors:   []string{"TestInstalledPythonWorkflowCarrierClosure"},
		},
		{"REQ-PROOFKIT-WORKFLOW-015", "proofkit.agent-workflow.project-navigation-public-cli"}: {
			witnessPath: "internal/app/project_status_command_test.go",
			selectors: []string{
				"TestNextCLI",
				"TestProjectStatusCLI",
				"TestProjectStatusCLIHonorsCanceledContextBeforeOutput",
				"TestProjectStatusOutputMatrix",
				"TestProjectStatusTransportFailureUsesOneBoundedWriteWithoutAtomicSinkClaim",
				"TestStatusCLI",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-015", "proofkit.agent-workflow.project-navigation-version-edge"}: {
			witnessPath: "internal/app/project_navigation_version_edge_test.go",
			selectors:   []string{"TestProjectNavigationVersionEdgeClosesPublicRoutes"},
		},
		{"REQ-PROOFKIT-WORKFLOW-018", "proofkit.agent-workflow.integration-installed-carriers"}: {
			commandIDs:         []string{"proofkit.go-test", "proofkit.package-artifact"},
			environmentClasses: []string{"local-go", "local-go-python"},
			witnessPath:        "internal/tools/workflowsmoke/workflow_smoke_test.go",
			selectors:          []string{"TestVerifyAcceptsApplicationCLI", "TestVerifyRejectsCarrierContractMutations"},
		},
		{"REQ-PROOFKIT-WORKFLOW-016", "proofkit.agent-workflow.integration-capability-and-carrier-identity"}: {
			witnessPath: "internal/app/agent_integration_command_test.go",
			selectors:   []string{"TestIntegrationCapabilityIdentityScope", "TestIntegrationSourcesAreCarrierIndependent"},
		},
		{"REQ-PROOFKIT-WORKFLOW-016", "proofkit.agent-workflow.integration-portable-source"}: {
			witnessPath: "internal/command/agentintegration/source_test.go",
			selectors:   []string{"TestSourceBindsPortableConsumedContracts", "TestSourceRejectsUnboundCapabilities"},
		},
		{"REQ-PROOFKIT-WORKFLOW-017", "proofkit.agent-workflow.integration-bounded-read-only-classification"}: {
			witnessPath: "internal/command/agentintegration/check_test.go",
			selectors: []string{
				"TestCheckInvalidRootsAreOperationErrors", "TestCheckPortableAliasesAreOperationErrors", "TestCheckProjectionHasOnlyAdmittedFields",
				"TestCheckRejectsEverySymlinkComponentWithoutFollowing", "TestCheckRejectsZeroDocumentBeforeInspection",
				"TestCheckStatesAreReadOnlyAndPrivate", "TestCheckUsesOneLeaseAndStrictReadBounds",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-017", "proofkit.agent-workflow.integration-fifo-denial"}: {
			witnessPath: "internal/command/agentintegration/check_unix_test.go",
			selectors:   []string{"TestCheckFIFONeverRead"},
		},
		{"REQ-PROOFKIT-WORKFLOW-017", "proofkit.agent-workflow.integration-operational-failure-and-cohort"}: {
			witnessPath: "internal/command/agentintegration/check_test.go",
			selectors: []string{
				"TestCheckCancellationBeforeAndAfterObservation", "TestCheckCleanupFailureInvalidatesEveryState", "TestCheckDetectsChangesWithinAnObservation",
				"TestCheckFileIOAndCleanupFailures", "TestCheckOpenErrorsAreNotMissingOrInvalid", "TestCheckPermissionDeniedIsNotMissing",
				"TestCheckReobservesBytesStateAndOpenedIdentityIndependently",
				"TestCheckRouteWitnessIgnoresUnrelatedSiblingWrites", "TestCheckRouteWitnessRejectsZeroInEveryState",
				"TestCheckVerifiesRootAfterBothObservations",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-017", "proofkit.agent-workflow.integration-complete-route-reobservation"}: {
			witnessPath: "internal/command/agentintegration/check_unix_test.go",
			selectors:   []string{"TestCheckReobservesCompleteRoute"},
		},
		{"REQ-PROOFKIT-WORKFLOW-017", "proofkit.agent-workflow.integration-inspection-route-capability"}: {
			witnessPath: "internal/kernel/repositorytransaction/control_inspection_test.go",
			selectors:   []string{"TestInspectionLeaseObservedOpenPreservesWitnessAndReadCapability", "TestInspectionLeaseObservedRouteBindsRootAndMissingPosition"},
		},
		{"REQ-PROOFKIT-WORKFLOW-017", "proofkit.agent-workflow.integration-opaque-route-observation"}: {
			witnessPath: "internal/kernel/rootpath/observation_unix_test.go",
			selectors: []string{
				"TestObservedOpenBindsRealRouteChangesWithoutSiblingMetadata", "TestObservedOpenPreservesLegacyResultsAndPrivateWitness",
				"TestObservedOpenRejectsAdmissionModeDriftAndCleanup", "TestRouteObservationEqualityBindsEveryOperand",
			},
		},
		{"REQ-PROOFKIT-WORKFLOW-017", "proofkit.agent-workflow.integration-pre-io-cli-admission"}: {
			witnessPath: "internal/app/agent_integration_command_test.go",
			selectors:   []string{"TestIntegrationCheckCLI"},
		},
		{"REQ-PROOFKIT-WORKFLOW-018", "proofkit.agent-workflow.integration-contract-and-route-closure"}: {
			commandIDs:  []string{"proofkit.command-contract-check", "proofkit.go-test"},
			witnessPath: "internal/app/cli_contract_test.go",
			selectors:   []string{"TestCLIContractMatchesDispatcherAndHelp", "TestCLIContractsAreCompleteGeneratedAndWitnessBound", "TestContractMapDecisionTreeHasThreeCells"},
		},
		{"REQ-PROOFKIT-WORKFLOW-018", "proofkit.agent-workflow.integration-public-cli"}: {
			witnessPath: "internal/app/agent_integration_command_test.go",
			selectors:   []string{"TestIntegrationCancellationBeforeOutput", "TestIntegrationCheckCLI", "TestIntegrationCommandsExactRootShapes", "TestIntegrationSourceCLI"},
		},
		{"REQ-PROOFKIT-WORKFLOW-018", "proofkit.agent-workflow.integration-installed-npm-carrier-closure"}: {
			witnessPath: "internal/tools/packageverify/workflow_carrier_test.go",
			selectors:   []string{"TestInstalledNPMWorkflowCarrierClosure"},
		},
		{"REQ-PROOFKIT-WORKFLOW-018", "proofkit.agent-workflow.integration-installed-wheel-carrier-closure"}: {
			witnessPath: "internal/tools/pythonpackage/workflow_carrier_test.go",
			selectors:   []string{"TestInstalledPythonWorkflowCarrierClosure"},
		},
		{"REQ-PROOFKIT-WORKFLOW-018", "proofkit.agent-workflow.integration-version-edge"}: {
			witnessPath: "internal/app/integration_version_edge_test.go",
			selectors:   []string{"TestIntegrationVersionEdgeClosesCompletePublicABIDiff"},
		},
		{"REQ-PROOFKIT-WORKFLOW-018", "proofkit.agent-workflow.integration-public-abi-mutations"}: {
			witnessPath: "internal/app/public_abi_mutation_test.go",
			selectors:   []string{"TestIntegrationVersionEdgeRejectsUndeclaredPublicABIDrift"},
		},
		{"REQ-PROOFKIT-PACKAGE-001", "proofkit.package-boundary.root-export-and-deep-import-denial"}: {
			witnessPath: "internal/tools/packageverify/main_test.go",
			selectors:   []string{"TestVerifyRootPackageRejectsEachForbiddenRootEntry"},
		},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.launcher-profile-admission"}: {
			witnessPath: "internal/kernel/cliexec/cliexec_test.go",
			selectors:   []string{"TestLauncherProfileAdmissionMatrix"},
		},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.generated-command-field-inventory"}: {
			witnessPath: "internal/app/invocation_profile_test.go",
			selectors: []string{
				"TestGeneratedCommandInvocationProfileFieldInventory",
				"TestGeneratedCommandInvocationProfileRouteClosure",
			},
		},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.generated-command-caller-preservation"}: {
			witnessPath: "internal/command/gradualadoption/gradualadoption_test.go",
			selectors:   []string{"TestBootstrapPreservesCallerDisplayCommandInGuidancePayload"},
		},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.cli-output-root-witnesses"}: {
			witnessPath: "internal/app/cli_abi_test.go",
			selectors: []string{
				"TestAdoptionContractEnvelopeCLIABI",
				"TestAgentRouteEnvelopeModesUseExactRootShapes",
				"TestRequirementAuthoringPlanOutputUsesVersionedRootShape",
				"TestSelfCheckOutputUsesExactRootShape",
				"TestStandaloneMultiVariantCommandsUseExactRootShapes",
			},
		},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.project-status-output-root-witnesses"}: {
			witnessPath: "internal/app/project_status_command_test.go",
			selectors: []string{
				"TestNextOutputUsesExactRootShape",
				"TestStatusOutputUsesExactRootShape",
			},
		},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.adoption-materialization-output-root-witnesses"}: {
			witnessPath: "internal/app/adoption_materialization_command_test.go",
			selectors: []string{
				"TestAdoptMaterializeApplyOutputUsesExactRootShape",
				"TestAdoptMaterializePlanOutputUsesExactRootShape",
				"TestAdoptMaterializeRecoverOutputUsesExactRootShape",
			},
		},
		{"REQ-PROOFKIT-PACKAGE-003", "proofkit.package-boundary.outside-consumer-artifact"}: {
			witnessPath: "internal/tools/packageverify/main_test.go",
			selectors: []string{
				"TestExactTarballOnboardingTrace",
				"TestInstalledCommandRouteBijectionBindsCommandIdentity",
				"TestInstalledNPMCarrierIsExactRegularTarballProjection",
				"TestVerifyPackedOwnerRecordsRejectsSourceArtifactContentDrift",
			},
		},
		{"REQ-PROOFKIT-PACKAGE-004", "proofkit.package-boundary.ci-receipt-anchor"}: {
			witnessPath: "scripts/validate-self-hosting-receipts_test.go",
			selectors: []string{
				"TestReceiptIDKeepsLocalAndCIIdentitiesDistinct",
				"TestRunInvokesEveryRequiredSelfHostingAdmissionBoundary",
			},
		},
		{"REQ-PROOFKIT-PACKAGE-004", "proofkit.package-boundary.self-hosting-report-verdict"}: {
			witnessPath: "scripts/validate-self-hosting-receipts_test.go",
			selectors:   []string{"TestRunProofkitVerdictCases"},
		},
		{"REQ-PROOFKIT-PACKAGE-005", "proofkit.package-boundary.merge-critical-runtime-preconditions"}: {
			witnessPath: "scripts/workflow_runtime_preconditions_test.go",
			selectors:   []string{"TestCISourceQualityInstallsPythonBeforeLifecycleTests"},
		},
		{"REQ-PROOFKIT-PACKAGE-006", "proofkit.package-boundary.python-wheel-candidate"}: {
			witnessPath: "scripts/validate-self-hosting-receipts_test.go",
			selectors:   []string{"TestPythonArtifactRefsRejectEachWheelIdentityDefect"},
		},
		{"REQ-PROOFKIT-PACKAGE-006", "proofkit.package-boundary.python-wheel-generated-continuation"}: {
			witnessPath: "internal/tools/pythonpackage/continuation_test.go",
			selectors: []string{
				"TestExactDisplayedRouteOperandsRejectsWhitespaceAndExpansionMutants",
				"TestInstalledPythonCarrierRejectsContractReplacementRemovalAndSymlink",
				"TestInstalledPythonCommandRoutesRequireExactContractBijection",
				"TestInstalledWheelContinuationUsesExactPythonModuleProfileWithoutNPM",
				"TestPipInstallArgumentsAreIsolatedAndOffline",
				"TestPythonVerificationEnvironmentRemovesAmbientImportControls",
			},
		},
		{"REQ-PROOFKIT-PACKAGE-007", "proofkit.package-boundary.package-public-docs-no-mutable-release-facts"}: {
			witnessPath: "internal/tools/packageverify/main_test.go",
			selectors:   []string{"TestVerifyNoStalePackageDocsRejectsMutableReleaseFactsInMarkdown"},
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-abi-golden"}: {
			witnessPath: "internal/app/cli_abi_test.go",
			selectors: []string{
				"TestAdoptionContractEnvelopeCLIABI",
				"TestAgentRouteEnvelopeModesUseExactRootShapes",
				"TestRequiredInputCommandsRouteStructuralErrorsByMode",
				"TestRequirementAuthoringPlanOutputUsesVersionedRootShape",
				"TestRequirementBrowserOneShotCLIOutputVariants",
				"TestSelfCheckOutputUsesExactRootShape",
				"TestStandaloneMultiVariantCommandsUseExactRootShapes",
			},
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.project-status-cli-abi"}: {
			witnessPath: "internal/app/project_status_command_test.go",
			selectors: []string{
				"TestNextOutputUsesExactRootShape",
				"TestStatusOutputUsesExactRootShape",
			},
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.adoption-materialization-cli-abi"}: {
			witnessPath: "internal/app/adoption_materialization_command_test.go",
			selectors: []string{
				"TestAdoptMaterializeApplyOutputUsesExactRootShape",
				"TestAdoptMaterializePlanOutputUsesExactRootShape",
				"TestAdoptMaterializeRecoverOutputUsesExactRootShape",
			},
		},
		{"REQ-PROOFKIT-QUALITY-001", "proofkit.supply-chain-quality.release-attestation-wiring"}: {
			witnessPath: "scripts/validate-self-hosting-receipts_test.go",
			selectors:   []string{"TestReleaseWorkflowRetainsReleaseAssetAndPostCreateEvidenceClosure"},
		},
		{"REQ-PROOFKIT-QUALITY-001", "proofkit.supply-chain-quality.retained-evidence-manifest"}: {
			witnessPath: "internal/tools/retainedevidence/manifest_test.go",
			selectors: []string{
				"TestManifestRejectsUnboundAttestationAndSymlink",
				"TestManifestUsesDownloadableArtifactPaths",
			},
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-contract-topology"}: {
			witnessPath: "internal/app/cli_contract_test.go",
			selectors: []string{
				"TestCLIConditionModelClosesAdoptionOutputRoutes",
				"TestCommandDescriptorContractParityRejectsMutations",
			},
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-output-witness-contract"}: {
			witnessPath: "internal/app/cli_output_witness_contract_test.go",
			selectors:   []string{"TestRootDistinctOutputWitnessBindingsAreExact"},
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-output-schema-evolution"}: {
			witnessPath: "internal/app/cli_contract_test.go",
			selectors:   []string{"TestRequirementCoverageViewBreakingRootUsesVersionedOutputContract"},
		},
		{"REQ-PROOFKIT-QUALITY-005", "proofkit.supply-chain-quality.codeql-permission-separation"}: {
			witnessPath: "scripts/workflow_security_scanner_oracles_test.go",
			selectors:   []string{"TestSecurityScannerWorkflowsSeparateProviderPublicationPermissions"},
		},
		{"REQ-PROOFKIT-QUALITY-006", "proofkit.supply-chain-quality.osv-permission-separation"}: {
			witnessPath: "scripts/workflow_security_scanner_oracles_test.go",
			selectors: []string{
				"TestOSVSourceScanFailsForEveryNonzeroScannerStatus",
				"TestSecurityScannerWorkflowsSeparateProviderPublicationPermissions",
			},
		},
		{"REQ-PROOFKIT-QUALITY-007", "proofkit.supply-chain-quality.scorecard-permission-and-publication-inputs"}: {
			witnessPath: "scripts/workflow_security_scanner_oracles_test.go",
			selectors: []string{
				"TestScorecardPublicPublishDeclaresRequiredOutputInputs",
				"TestSecurityScannerWorkflowsSeparateProviderPublicationPermissions",
			},
		},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.artifact-file-boundary"}: {
			witnessPath: "internal/tools/artifactfile/file_test.go",
			selectors: []string{
				"TestOperationsRejectFinalSymlinkWithoutTargetMutation",
				"TestOperationsRejectSymlinkComponentsWithoutOutsideMutation",
				"TestReadBoundedRejectsUnrepresentableLimit",
				"TestWriteReadAndRemoveRoundTrip",
			},
		},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.artifact-file-nonblocking-open"}: {
			witnessPath: "internal/tools/artifactfile/file_unix_test.go",
			selectors:   []string{"TestReadBoundedRejectsFIFOWithoutBlocking"},
		},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.coverage-metrics"}: {
			witnessPath: "internal/tools/coveragemetrics/main_test.go",
			selectors: []string{
				"TestEachCommandRouteClosureConjunctHasIndependentFalsifier",
				"TestEachLinkageDeadZoneConjunctHasIndependentFalsifier",
				"TestInvalidateMetricsFileRejectsSymlinkParentWithoutDeletingOutsideFile",
				"TestWriteMetricsFileRejectsSymlinkEscapeWithoutMutation",
			},
		},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.command-oracle-execution-ledger"}: {
			witnessPath: "internal/tools/commandoracle/execute_test.go",
			selectors: []string{
				"TestExecuteBindsMaterializedSourceCandidatesAndRuntimeEvents",
				"TestRunGoTestCommandTerminatesImmediatelyWhenStderrExceedsBound",
				"TestRunGoTestsDoesNotExecuteCrossPackageNameMatches",
				"TestRunGoTestsTerminatesOnContextDeadline",
				"TestValidateCurrentRejectsProducerUnreachableCandidateProjection",
			},
		},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.command-oracle-counterfeit-corpus"}: {
			witnessPath: "internal/tools/commandoracle/corpus_test.go",
			selectors: []string{
				"TestCounterfeitCorpusClosesRequiredAxes",
				"TestCounterfeitCorpusClosureRejectsMissingRequiredAxes",
				"TestEachCounterfeitCaseProducesItsCheckedInDecision",
			},
		},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.command-oracle-source-snapshot"}: {
			witnessPath: "internal/tools/repositorysnapshot/snapshot_test.go",
			selectors: []string{
				"TestCaptureContextTerminatesCanceledGitProcessGroup",
				"TestCaptureContextTerminatesGitProcessGroupOnOutputOverflow",
				"TestCaptureRejectsSuccessfulGitDiagnosticsWithoutEcho",
				"TestMaterializeBindsCopiedBytesAndRejectsLiveMutation",
				"TestMaterializeRejectsSymlinkAndNonEmptyDestination",
				"TestMaterializeRejectsSymlinkedDestinationInsideSource",
				"TestValidRevisionAdmitsOnlyGitObjectIdentityAndOptionalSnapshotDigest",
				"TestValidateMaterializedRejectsSurplusFile",
			},
		},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.binding-selector-executability"}: {
			witnessPath: "internal/tools/coveragemetrics/main_test.go",
			selectors: []string{
				"TestBindingWitnessSelectorsAcceptUnnamedGoTestParameter",
				"TestBindingWitnessSelectorsRejectInvalidGoTestSignature",
				"TestBindingWitnessSelectorsRejectMissingSemanticOwner",
				"TestBindingWitnessSelectorsRejectNonTestAndBuildExcludedFiles",
				"TestBindingWitnessSelectorsRejectVacuousTestBody",
				"TestBindingWitnessSelectorsRequireExactCriticalInventories",
			},
		},
		{"REQ-PROOFKIT-QUALITY-011", "proofkit.supply-chain-quality.ci-required-aggregate-exactness"}: {
			witnessPath: "scripts/workflow_package_gate_oracle_test.go",
			selectors: []string{
				"TestCIRequiredAggregateRejectsExecutionOverrides",
				"TestCIRequiredAggregateRejectsNeutralizedScript",
				"TestCIRequiredAggregateRejectsPlatformSmokeSubstitution",
				"TestCIWorkflowDeclaresFailClosedRequiredAggregate",
			},
		},
		{"REQ-PROOFKIT-QUALITY-013", "proofkit.supply-chain-quality.workflow-package-gate-oracle"}: {
			witnessPath: "scripts/workflow_package_gate_oracle_test.go",
			selectors: []string{
				"TestCIWorkflowDeclaresFailClosedRequiredAggregate",
				"TestNeedsListNormalizesStringAndList",
				"TestPackageGateWorkflowOracleAcceptsOwnerCIAndReleaseWorkflows",
				"TestPackageGateWorkflowOracleAdmitsAlwaysWithNeedSuccess",
				"TestPackageGateWorkflowOracleAdmitsLaterAlwaysWithSuccess",
				"TestPackageGateWorkflowOracleAdmitsPrivateAttestationBypass",
				"TestPackageGateWorkflowOracleRejectsAlwaysWithoutNeedSuccess",
				"TestPackageGateWorkflowOracleRejectsDisabledAndShadowedEvidence",
				"TestPackageGateWorkflowOracleRejectsDuplicatePriorStepName",
				"TestPackageGateWorkflowOracleRejectsExecutionOverrides",
				"TestPackageGateWorkflowOracleRejectsLateRequiredPriorStep",
				"TestPackageGateWorkflowOracleRejectsMissingWorkflowPermissionFloor",
				"TestPackageGateWorkflowOracleRejectsNeedSuccessBypass",
				"TestPackageGateWorkflowOracleRejectsRequiredPriorExecutionOverride",
				"TestPackageGateWorkflowOracleRejectsUnusedAllowedStepEnvironment",
				"TestPackageGateWorkflowOracleRejectsWrongPriorStepCommand",
				"TestWorkflowGuardExpressionsRejectNeutralization",
			},
		},
		{"REQ-PROOFKIT-QUALITY-016", "proofkit.supply-chain-quality.release-platform-python-wheels"}: {
			witnessPath: "internal/tools/pythonpackage/metadata_test.go",
			selectors: []string{
				"TestREADMEPlatformAndPythonProjection",
				"TestReleaseTargetsProjectExactPythonWheelMetadata",
				"TestVerifyWheelContentsRequiresExactWheelMetadata",
			},
		},
		{"REQ-PROOFKIT-QUALITY-019", "proofkit.supply-chain-quality.installed-package-json-abi-smoke"}: {
			witnessPath: "internal/tools/packageverify/main_test.go",
			selectors: []string{
				"TestExactTarballOnboardingTrace",
				"TestInstalledInvocationRequiresAuthoredOrderAndExactCommandToken",
				"TestInstalledNPMCarrierIsExactRegularTarballProjection",
				"TestInstalledREADMEFirstInputPreservesJSONExampleBytes",
				"TestInstalledREADMEFirstInputUsesBoundedLiteralShellWords",
				"TestLiteralShellWordsConsumesLongBackslashRun",
				"TestOnboardingTraceCoversEveryDiscoveredPresetAndREADMEInput",
				"TestVerifyPackedOwnerRecordsRejectsSourceArtifactContentDrift",
			},
		},
		{"REQ-PROOFKIT-QUALITY-023", "proofkit.supply-chain-quality.release-closeout-npm-byte-admission"}: {
			witnessPath: "internal/tools/releasecloseoutinput/main_test.go",
			selectors: []string{
				"TestBuildInputFailsClosedForEachBlockingEvidenceClass",
				"TestPackRecordBytesMatchEnforcesByteLimit",
			},
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-manifest-json-abi-registry-evidence"}: {
			witnessPath: "internal/tools/releasemanifest/main_test.go",
			selectors: []string{
				"TestNPMRegistryAuthorityFlowsFromAdmittedFileToPublishedChannel",
				"TestNPMRegistryPublicationRequiresTypedAuthorityEvidence",
			},
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.npm-registry-authority-producer"}: {
			witnessPath: "internal/tools/npmregistry/main_test.go",
			selectors: []string{
				"TestRunBuildsCanonicalTypedRegistryEvidence",
				"TestRunRejectsRegistryPackageSetSubstitution",
			},
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.npm-registry-workflow-delegation"}: {
			witnessPath: "scripts/validate-self-hosting-receipts_test.go",
			selectors:   []string{"TestReleaseWorkflowDelegatesNPMRegistryEvidenceToRepositoryOwner"},
		},
		{"REQ-PROOFKIT-QUALITY-022", "proofkit.supply-chain-quality.browser-failure-diagnostics-retention"}: {
			witnessPath: "scripts/workflow_browser_runtime_oracle_test.go",
			selectors:   []string{"TestCIBrowserRuntimeRetainsFailureDiagnosticsWithoutPublishingProof"},
		},
		{"REQ-PROOFKIT-QUALITY-023", "proofkit.supply-chain-quality.python-wheel-platform-byte-compatibility"}: {
			witnessPath: "internal/tools/pythonpackage/metadata_test.go",
			selectors: []string{
				"TestMachOMinimumMacOSAcceptsLegacyVersionCommand",
				"TestMachOMinimumMacOSRejectsTruncatedBuildVersion",
				"TestVerifyWheelContentsAcceptsDarwinTagAtOrAboveMachOMinimum",
				"TestVerifyWheelContentsRejectsDarwinTagBelowMachOMinimum",
			},
		},
		{"REQ-PROOFKIT-QUALITY-023", "proofkit.supply-chain-quality.python-wheel-resource-bounds"}: {
			witnessPath: "internal/tools/pythonpackage/metadata_test.go",
			selectors: []string{
				"TestVerifyWheelContentsRejectsOversizedCompressedEntryBeforeDecompression",
				"TestVerifyWheelContentsRejectsOversizedEntryBeforeDecompression",
			},
		},
		{"REQ-PROOFKIT-QUALITY-023", "proofkit.supply-chain-quality.wrapper-platform-bijection"}: {
			witnessPath: "internal/tools/packagebuild/main_test.go",
			selectors:   []string{"TestWrapperScriptRoutesEveryReleasePlatformTarget"},
		},
		{"REQ-PROOFKIT-QUALITY-015", "proofkit.supply-chain-quality.release-closeout-completion-criteria"}: {
			witnessPath: "internal/tools/releasecloseoutinput/main_test.go",
			selectors: []string{
				"TestBuildInputFailsClosedForEachBlockingEvidenceClass",
				"TestSelfEvidenceInvokesCurrentCommandOracleOwner",
				"TestSelfEvidenceRejectsProducerUnreachableCommandOracleRef",
			},
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-change-record-projection"}: {
			witnessPath: "internal/tools/releasechange/record_test.go",
			selectors: []string{
				"TestAdmitEnforcesVersionedChangeClass",
				"TestCurrentChangeRecordNamesReviewedSemanticChanges",
				"TestRenderStatesPreOneExactPinPolicy",
			},
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.retained-evidence-artifact-topology"}: {
			witnessPath: "internal/tools/retainedevidence/manifest_test.go",
			selectors:   []string{"TestVerifyRejectsManifestAddressDrift"},
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-closeout-change-record"}: {
			witnessPath: "internal/tools/releasecloseoutinput/main_test.go",
			selectors:   []string{"TestBuildInputFailsClosedForEachBlockingEvidenceClass"},
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-predecessor-lineage"}: {
			witnessPath: "internal/tools/releasepreflight/main_test.go",
			selectors: []string{
				"TestRunNPMLineageUsesAdmittedRecordAndProviderIdentity",
				"TestValidateNPMReleaseLineage",
			},
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-predecessor-lineage-workflow"}: {
			witnessPath: "scripts/validate-self-hosting-receipts_test.go",
			selectors:   []string{"TestReleaseWorkflowCandidateEvidenceAllowsExistingNPMByteMatch"},
		},
		{"REQ-PROOFKIT-QUALITY-025", "proofkit.supply-chain-quality.workflow-source-oracles"}: {
			witnessPath: "scripts/workflow_source_oracles_test.go",
			selectors: []string{
				"TestExistingReleasePathIsReadOnlyAndFailsOnDrift",
				"TestWorkflowClosedKeyAdmission",
				"TestWorkflowExternalActionsUseFullCommitSHAs",
			},
		},
		{"REQ-PROOFKIT-SPEC-011", "proofkit.spec-proof-core.adoption-contract-envelope-cli-abi"}: {
			witnessPath: "internal/app/cli_abi_test.go",
			selectors:   []string{"TestAdoptionContractEnvelopeCLIABI"},
		},
		{"REQ-PROOFKIT-SPEC-007", "proofkit.spec-proof-core.canonical-command-input-admission"}: {
			witnessPath: "internal/app/command_coverage_test.go",
			selectors:   []string{"TestRequiredInputCommandsRejectMalformedCallerRecords"},
		},
		{"REQ-PROOFKIT-SPEC-007", "proofkit.spec-proof-core.canonical-input-admission"}: {
			witnessPath: "internal/kernel/admission/json_test.go",
			selectors:   []string{"TestDecodeTypedJSONUsesStrictAdmission"},
		},
		{"REQ-PROOFKIT-SPEC-013", "proofkit.spec-proof-core.receipt-trust-status-vocabulary-admission"}: {
			witnessPath: "internal/command/receipttrustclass/receipt_trust_class_test.go",
			selectors:   []string{"TestBuildRejectsHigherRankThatWeakensMinimumTrustSemantics"},
		},
		{"REQ-PROOFKIT-SPEC-021", "proofkit.spec-proof-core.requirement-browser-one-shot-cleanup"}: {
			witnessPath: "internal/command/requirementbrowser/server_test.go",
			selectors: []string{
				"TestServeOneShotDoesNotReadCompletedDoneTwice",
				"TestServeOneShotReturnsCleanupFailuresWithoutWritingTerminalPacket",
				"TestServeOneShotWaitsForDoneBeforeWritingTerminalPacket",
			},
		},
		{"REQ-PROOFKIT-SPEC-006", "proofkit.spec-proof-core.test-inventory-and-coverage-view"}: {
			witnessPath: "internal/command/requirementcoverageview/output_closure_test.go",
			selectors: []string{
				"TestAdmitOutputRejectsCompactProjectionDrift",
				"TestAdmitOutputRejectsMissingInverseParentProjection",
				"TestAdmitOutputRejectsNonCanonicalWireProjectionText",
				"TestAdmitOutputRejectsRemovedValidUnmappedInventoryEntry",
				"TestAdmitOutputReplaysFailedInventoryQualitySemantics",
				"TestAdmitOutputReplaysFullRepositorySourceOwnerScopeFailures",
				"TestAdmitOutputReplaysOwnerScopeFailures",
				"TestAdmitOutputRequiresEveryCoverageBasisField",
				"TestAdmitOutputRequiresEveryDeclaredRootField",
				"TestAdmitOutputRetainsFailedInventoryEntriesWithoutProjectedParents",
				"TestAdmitOutputValidatesEveryCoverageRowMetadataField",
			},
		},
		{"REQ-PROOFKIT-SPEC-006", "proofkit.spec-proof-core.declared-route-mapping-without-assurance"}: {
			witnessPath: "internal/command/requirementcoverageview/requirementcoverageview_test.go",
			selectors:   []string{"TestBuildJSONMissingSelectorRemainsMappingOnly"},
		},
		{"REQ-PROOFKIT-SPEC-012", "proofkit.spec-proof-core.requirement-authoring-ref-provenance"}: {
			witnessPath: "internal/command/requirementauthoringplan/requirement_authoring_plan_test.go",
			selectors:   []string{"TestBuildPreservesDigestBoundAuthoringRefIdentity"},
		},
		{"REQ-PROOFKIT-SPEC-026", "proofkit.spec-proof-core.agent-route-brief-cli-abi"}: {
			witnessPath: "internal/app/cli_abi_test.go",
			selectors:   []string{"TestAgentRouteEnvelopeModesUseExactRootShapes"},
		},
		{"REQ-PROOFKIT-SPEC-026", "proofkit.spec-proof-core.agent-route-brief-projection"}: {
			witnessPath: "internal/command/agentroute/brief_test.go",
			selectors: []string{
				"TestAgentBriefBindsLauncherContextThatAffectsReportDigest",
				"TestAgentBriefClosesEverySelectedCommandInputReference",
				"TestAgentBriefCompactsAtDeclaredByteBoundary",
				"TestAgentBriefIsBoundedAndFullEnvelopeRemainsAvailable",
				"TestAgentBriefNamesCompleteInputBundleBlocker",
				"TestAgentBriefPreservesBlockedRouteOmissionsAndUnknownReportBlockers",
				"TestBriefBlockerBoundDominatesMapMaterialization",
				"TestBuildEnvelopeCapsBlockersAndCountsOmittedDetails",
				"TestBuildEnvelopeCompactsOversizedArgvWithoutLosingActionIdentity",
			},
		},
		{"REQ-PROOFKIT-SPEC-026", "proofkit.spec-proof-core.agent-route-flag-pre-read-admission"}: {
			witnessPath: "internal/app/app_test.go",
			selectors:   []string{"TestAgentRouteModeAdmissionPrecedesInputRead"},
		},
		{"REQ-PROOFKIT-SPEC-026", "proofkit.spec-proof-core.agent-route-report-contract-closure"}: {
			witnessPath: "internal/app/cli_contract_test.go",
			selectors:   []string{"TestAgentRouteOutputContractPreservesReportSemantics"},
		},
		{"REQ-PROOFKIT-SPEC-026", "proofkit.spec-proof-core.agent-route-brief-version-edge"}: {
			witnessPath: "internal/app/agent_route_version_edge_test.go",
			selectors:   []string{"TestAgentRouteVersionEdgeClosesBriefDefaultMigration"},
		},
		{"REQ-PROOFKIT-SPEC-026", "proofkit.spec-proof-core.agent-route-materialized-ref-admission"}: {
			witnessPath: "internal/command/agentroute/agentroute_test.go",
			selectors:   []string{"TestBuildRejectsStdinTransportSentinelAsArtifactReference"},
		},
		{"REQ-PROOFKIT-SPEC-028", "proofkit.spec-proof-core.adoption-inventory-boundary"}: {
			witnessPath: "internal/command/repositoryinventory/repositoryinventory_test.go",
			selectors: []string{
				"TestCatalogRolePolicyIsExact",
				"TestInventoryIdentityBindsEverySemanticOperand",
				"TestInventoryOutputByteLimitIsExact",
				"TestReadRootInventoryClassifiesPartialBatchesWithoutRetainingUnknownNames",
				"TestScanDoesNotFollowUnknownSymlink",
				"TestScanEnforcesPreflightBoundsAndExplicitOmissions",
				"TestScanPolicyBoundariesAreExact",
				"TestScanProducesBoundedClosedInventory",
				"TestScanRejectsRecognizedSymlinkWithoutReadingTarget",
				"TestUnsupportedPlatformFailsBeforeOpeningRepositoryRoot",
			},
		},
		{"REQ-PROOFKIT-SPEC-028", "proofkit.spec-proof-core.adoption-inventory-nonblocking-open"}: {
			witnessPath: "internal/command/repositoryinventory/fifo_unix_test.go",
			selectors:   []string{"TestScanRejectsFIFOReplacementWithoutBlocking"},
		},
		{"REQ-PROOFKIT-SPEC-029", "proofkit.spec-proof-core.adoption-plan-authority-closure"}: {
			witnessPath: "internal/command/adoptionplan/adoptionplan_test.go",
			selectors: []string{
				"TestBuildRejectsUnknownIntentPresetAndForgedInventory",
				"TestBuildSeparatesAdoptionIntentFromCandidateAuthority",
				"TestBuildStackHintCannotChangeIntentTrustOrTasks",
				"TestPlanIdentityBindsIntentAndInventory",
				"TestPlanWireAdmissionIsDeterministicAndOwnerClosed",
			},
		},
		{"REQ-PROOFKIT-SPEC-029", "proofkit.spec-proof-core.adoption-plan-observational-stack"}: {
			witnessPath: "internal/command/adoptionplan/repository_classes_test.go",
			selectors:   []string{"TestPlanKeepsRepositoryClassesObservationalAndStackNeutral"},
		},
		{"REQ-PROOFKIT-SPEC-029", "proofkit.spec-proof-core.adoption-guidance-reference-closure"}: {
			witnessPath: "internal/command/nativeevidenceguidance/guidance_test.go",
			selectors:   []string{"TestGuidanceReferenceIsCompactAndOwnerBound"},
		},
		{"REQ-PROOFKIT-SPEC-030", "proofkit.spec-proof-core.adoption-plan-presentation-closure"}: {
			witnessPath: "internal/command/adoptionplan/adoptionplan_test.go",
			selectors: []string{
				"TestAdoptionPlanOutputAndTextBoundsAreExact",
				"TestTextProjectionPreservesJSONPlanSemantics",
			},
		},
		{"REQ-PROOFKIT-SPEC-027", "proofkit.spec-proof-core.adoption-front-door-whole-cli"}: {
			witnessPath: "internal/app/adoption_front_door_command_test.go",
			selectors:   []string{"TestAdoptionFrontDoorCLI"},
		},
		{"REQ-PROOFKIT-SPEC-018", "proofkit.spec-proof-core.command-route-contract-closure"}: {
			witnessPath: "internal/tools/commandcontractgen/main_test.go",
			selectors: []string{
				"TestCommandRoutesAreBoundedSafeAndUnambiguous",
				"TestRenderRejectsIncompleteAndStaleCommandContracts",
			},
		},
		{"REQ-PROOFKIT-SPEC-018", "proofkit.spec-proof-core.command-route-generated-adapter"}: {
			witnessPath: "internal/command/jsonreportcliadaptersource/json_report_cli_adapter_source_test.go",
			selectors:   []string{"TestGeneratedSourceAdmitsBoundedCanonicalCommandRoutes"},
		},
		{"REQ-PROOFKIT-SPEC-018", "proofkit.spec-proof-core.command-route-installed-contract"}: {
			witnessPath: "internal/tools/installedclicontract/contract_test.go",
			selectors: []string{
				"TestAdmitCommandRouteTokenBoundariesAreExact",
				"TestAdmitRequiresExactCommandRouteGrammarProjection",
			},
		},
		{"REQ-PROOFKIT-SPEC-018", "proofkit.spec-proof-core.command-route-kernel-owner"}: {
			witnessPath: "internal/kernel/commandroute/route_test.go",
			selectors: []string{
				"TestGrammarBoundariesAreExact",
				"TestOmittedRoutePolicyUsesStableCommandIdentity",
				"TestParseRequiresCanonicalSeparatorAndRoundTrip",
			},
		},
		{"REQ-PROOFKIT-SPEC-031", "proofkit.spec-proof-core.adoption-version-edge-closure"}: {
			witnessPath: "internal/app/adoption_front_door_version_edge_test.go",
			selectors: []string{
				"TestAdoptionFrontDoorVersionEdgeClosesInitRetirement",
				"TestAdoptionFrontDoorVersionEdgeRejectsDigestBoundInventoryContradiction",
				"TestRetiredInitRouteHasNoPublicDispatcher",
			},
		},
		{"REQ-PROOFKIT-SPEC-032", "proofkit.spec-proof-core.adoption-materialization-owner-closure"}: {
			witnessPath: "internal/command/adoptionmaterialization/adoptionmaterialization_test.go",
			selectors: []string{
				"TestApplyBlocksStaleMutationButAcceptsLostAcknowledgementRetry",
				"TestMaterializationOutputAdmissionRejectsCrossOwnerMutants",
				"TestMaterializationRejectsCrossRecordDriftAndManifestMutation",
				"TestMaterializationWholeChainIsCanonicalAndOwnerClosed",
				"TestReceiptAdmissionRejectsOperationAttributionMutants",
			},
		},
		{"REQ-PROOFKIT-SPEC-032", "proofkit.spec-proof-core.adoption-materialization-reference-closure"}: {
			witnessPath: "internal/command/adoptionmaterialization/closure_test.go",
			selectors: []string{
				"TestInventoryReferencesMustResolveThroughBindingEdges",
				"TestManifestAdmissionEqualsProducerImage",
				"TestPathRoleLedgerRejectsWriteReferenceCollisions",
				"TestRequirementProjectionRequiresClaimLevelParity",
			},
		},
		{"REQ-PROOFKIT-SPEC-032", "proofkit.spec-proof-core.adoption-materialization-whole-cli"}: {
			witnessPath: "internal/app/adoption_materialization_command_test.go",
			selectors:   []string{"TestAdoptionMaterializationCLI"},
		},
		{"REQ-PROOFKIT-SPEC-033", "proofkit.spec-proof-core.repository-transaction-fault-recovery"}: {
			witnessPath: "internal/kernel/repositorytransaction/transaction_test.go",
			selectors: []string{
				"TestApplyAlreadySatisfiedRejectsConcurrentCooperativeWriter",
				"TestApplyFaultAfterFirstPublishRestoresExactBeforeState",
				"TestApplyRejectsConcurrentCooperativeWriter",
				"TestProcessInterruptionAtEveryMutationBoundaryIsRecoverable",
				"TestRecoverDoesNotInventIdentityForPartialPreparingJournal",
				"TestTransactionLockIsInterprocess",
			},
		},
		{"REQ-PROOFKIT-SPEC-033", "proofkit.spec-proof-core.repository-transaction-output-relations"}: {
			witnessPath: "internal/kernel/repositorytransaction/output_admission_test.go",
			selectors:   []string{"TestPlanAndResultOutputAdmissionRejectSemanticMutants"},
		},
		{"REQ-PROOFKIT-SPEC-033", "proofkit.spec-proof-core.repository-transaction-cleanup-state-matrix"}: {
			witnessPath: "internal/kernel/repositorytransaction/state_machine_test.go",
			selectors:   []string{"TestCleanupDurabilityFailureDoesNotClaimRecoverableState"},
		},
		{"REQ-PROOFKIT-SPEC-033", "proofkit.spec-proof-core.repository-transaction-filesystem-portable-path-identity"}: {
			witnessPath: "internal/kernel/repositorytransaction/plan_test.go",
			selectors:   []string{"TestBuildPlanRejectsFilesystemPortableAliases"},
		},
		{"REQ-PROOFKIT-SPEC-033", "proofkit.spec-proof-core.repository-transaction-portable-path-identity"}: {
			witnessPath: "internal/kernel/pathidentity/pathidentity_test.go",
			selectors:   []string{"TestPortableEquivalenceAndContainment"},
		},
		{"REQ-PROOFKIT-SPEC-033", "proofkit.spec-proof-core.repository-transaction-terminal-state"}: {
			witnessPath: "internal/kernel/repositorytransaction/invariant_test.go",
			selectors: []string{
				"TestAppliedTerminalReceiptReplaysCompleteResult",
				"TestApplyExecutesFrozenPlan",
				"TestCommittedRecoveryRejectsRollback",
				"TestMalformedRecoveryActionBlocksMutation",
				"TestPreparingFailureCannotClaimRollbackAfterTargetDivergence",
				"TestPreparingRecoveryRejectsResumeBeforeActionSelection",
				"TestPreparingRollbackAtomicallyReplacesPreviousTerminalReceipt",
				"TestReadyReplacementRetiresPreviousReceiptAndPreservesCompleteResult",
				"TestRecoveryActionAndTerminalReceiptAreStable",
				"TestRecoveryActionIsDurableBeforeDirectionalMutation",
				"TestUnknownRecoveryStateDoesNotAdoptExpectedIdentity",
			},
		},
		{"REQ-PROOFKIT-SPEC-034", "proofkit.spec-proof-core.adoption-materialization-version-edge"}: {
			witnessPath: "internal/app/adoption_materialization_version_edge_test.go",
			selectors: []string{
				"TestAdoptionMaterializationVersionEdgeClosesPublicCommands",
				"TestAdoptionMaterializationVersionEdgePreservesFrozenPredecessor",
				"TestAdoptionMaterializationVersionEdgeRejectsCoordinatedChangeRecordDrift",
			},
		},
		{"REQ-PROOFKIT-SPEC-035", "proofkit.spec-proof-core.project-navigation-version-edge"}: {
			witnessPath: "internal/app/project_navigation_version_edge_test.go",
			selectors: []string{
				"TestProjectNavigationVersionEdgeClosesPublicRoutes",
				"TestProjectNavigationVersionEdgePreservesFrozenPredecessor",
				"TestProjectNavigationVersionEdgeRejectsCoordinatedChangeRecordDrift",
			},
		},
		{"REQ-PROOFKIT-SPEC-035", "proofkit.spec-proof-core.project-navigation-public-abi-diff"}: {
			witnessPath: "internal/app/project_navigation_abi_closure_test.go",
			selectors:   []string{"TestProjectNavigationVersionEdgeClosesCompletePublicABIDiff"},
		},
		{"REQ-PROOFKIT-SPEC-035", "proofkit.spec-proof-core.project-navigation-public-abi-diff-mutations"}: {
			witnessPath: "internal/app/project_navigation_abi_mutation_test.go",
			selectors:   []string{"TestProjectNavigationVersionEdgeRejectsUndeclaredPublicABIDrift"},
		},
		{"REQ-PROOFKIT-RETIRE-006", "proofkit.consumer-infra-retirement.migration-parity-admission"}: {
			witnessPath: "internal/command/migrationparityadmission/migrationparityadmission_test.go",
			selectors:   []string{"TestBuildProjectsEveryCallerDeclaredStatusAndSummaryField"},
		},
	}
}
