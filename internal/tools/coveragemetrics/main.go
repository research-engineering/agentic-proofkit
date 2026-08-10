package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/gotestsource"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
)

const outputPath = "artifacts/proofkit/coverage-metrics.json"

var commandCoverageInventoryInput = app.CommandCoverageInventory

type requirementSource struct {
	Requirements []requirementRecord `json:"requirements"`
	SourceID     string              `json:"sourceId"`
}

type requirementRecord struct {
	ClaimLevel    string    `json:"claimLevel"`
	Lifecycle     lifecycle `json:"lifecycle"`
	RequirementID string    `json:"requirementId"`
}

type lifecycle struct {
	State string `json:"state"`
}

type bindingFile struct {
	Requirements []bindingRequirement `json:"requirements"`
	Bindings     []bindingScenario    `json:"bindings"`
}

type bindingRequirement struct {
	ClaimLevel    string `json:"claimLevel"`
	ProofState    string `json:"proofState"`
	RequirementID string `json:"requirementId"`
	SpecPath      string `json:"specPath"`
}

type bindingScenario struct {
	CommandIDs       []string          `json:"commandIds"`
	RequirementID    string            `json:"requirementId"`
	ScenarioID       string            `json:"scenarioId"`
	WitnessID        string            `json:"witnessId"`
	WitnessPath      string            `json:"witnessPath"`
	WitnessSelectors []witnessSelector `json:"witnessSelectors"`
}

type witnessSelector struct {
	Command  string `json:"command"`
	Selector string `json:"selector"`
}

type witnessPlan struct {
	Commands []struct {
		ID string `json:"id"`
	} `json:"commands"`
}

type cliContract struct {
	Commands []struct {
		Command string `json:"command"`
	} `json:"commands"`
}

type metrics struct {
	ArtifactKind  string              `json:"artifactKind"`
	SchemaVersion int                 `json:"schemaVersion"`
	Requirements  requirementMetrics  `json:"requirements"`
	ProofBindings proofBindingMetrics `json:"proofBindings"`
	WitnessPlan   witnessPlanMetrics  `json:"witnessPlan"`
	CLIContract   cliContractMetrics  `json:"cliContract"`
	CommandRoutes commandRouteMetrics `json:"commandRoutes"`
	DeadZones     deadZoneMetrics     `json:"deadZones"`
	NonClaims     []string            `json:"nonClaims"`
	Provenance    coverageProvenance  `json:"provenance"`
}

type coverageProvenance struct {
	GeneratedAt          string `json:"generatedAt"`
	ProducerCommandID    string `json:"producerCommandId"`
	SourceRevision       string `json:"sourceRevision"`
	SourceSnapshotDigest string `json:"sourceSnapshotDigest"`
}

type requirementMetrics struct {
	Active       int `json:"active"`
	Blocking     int `json:"blocking"`
	SourceFiles  int `json:"sourceFiles"`
	TotalRecords int `json:"totalRecords"`
}

type proofBindingMetrics struct {
	BoundRequirementCount         int `json:"boundRequirementCount"`
	ScenarioCount                 int `json:"scenarioCount"`
	WitnessBackedRequirementCount int `json:"witnessBackedRequirementCount"`
}

type witnessPlanMetrics struct {
	CommandCount int `json:"commandCount"`
}

type cliContractMetrics struct {
	CommandCount int      `json:"commandCount"`
	Commands     []string `json:"commands"`
}

type commandRouteMetrics struct {
	AdmittedInventoryEntryCount                       int      `json:"admittedInventoryEntryCount"`
	CommandCount                                      int      `json:"commandCount"`
	Commands                                          []string `json:"commands"`
	CommandWithoutProofRouteCandidateCount            int      `json:"commandWithoutProofRouteCandidateCount"`
	CommandsWithoutProofRouteCandidate                []string `json:"commandsWithoutProofRouteCandidate"`
	ContractOnlyCommandCount                          int      `json:"contractOnlyCommandCount"`
	ContractOnlyCommands                              []string `json:"contractOnlyCommands"`
	CommandWithoutDeclaredSemanticFalsifierRouteCount int      `json:"commandWithoutDeclaredSemanticFalsifierRouteCount"`
	CommandsWithoutDeclaredSemanticFalsifierRoute     []string `json:"commandsWithoutDeclaredSemanticFalsifierRoute"`
	RouteCount                                        int      `json:"routeCount"`
	RouteOnlyCommandCount                             int      `json:"routeOnlyCommandCount"`
	RouteOnlyCommands                                 []string `json:"routeOnlyCommands"`
	RouteSmokeCount                                   int      `json:"routeSmokeCount"`
	ProofRouteCandidateInventoryEntryCount            int      `json:"proofRouteCandidateInventoryEntryCount"`
	ProofRouteCandidateRouteCount                     int      `json:"proofRouteCandidateRouteCount"`
	DeclaredSemanticFalsifierRouteEntryCount          int      `json:"declaredSemanticFalsifierRouteEntryCount"`
	UnknownProofRouteCandidateRefs                    []string `json:"unknownProofRouteCandidateRefs"`
	UnknownProofRouteCandidateRefCount                int      `json:"unknownProofRouteCandidateRefCount"`
	UnknownDeclaredSemanticRouteCommandRefs           []string `json:"unknownDeclaredSemanticRouteCommandRefs"`
	UnknownDeclaredSemanticRouteCommandRefCount       int      `json:"unknownDeclaredSemanticRouteCommandRefCount"`
}

type deadZoneMetrics struct {
	BindingWithoutRequirementIDs  []string `json:"bindingWithoutRequirementIds"`
	RequirementWithoutBindingIDs  []string `json:"requirementWithoutBindingIds"`
	ScenarioWithoutCommandIDs     []string `json:"scenarioWithoutCommandIds"`
	ScenarioWithoutRequirementIDs []string `json:"scenarioWithoutRequirementIds"`
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	requirements, err := readRequirements()
	if err != nil {
		return err
	}
	bindings, err := readJSON[bindingFile]("proofkit/requirement-bindings.json")
	if err != nil {
		return err
	}
	witnesses, err := readJSON[witnessPlan]("proofkit/witness-plan.json")
	if err != nil {
		return err
	}
	contract, err := readJSON[cliContract]("proofkit/cli-contract.v2.json")
	if err != nil {
		return err
	}
	commandInventory, err := readCommandCoverageInventory()
	if err != nil {
		out := buildMetrics(requirements, bindings, witnesses, contract, testevidenceinventory.Inventory{})
		return writeMetrics(out, err)
	}
	out := buildMetrics(requirements, bindings, witnesses, contract, commandInventory)
	if err := bindCurrentSourceProvenance(&out); err != nil {
		return writeMetrics(out, err)
	}
	closeoutErr := errors.Join(
		requireCommandRouteInventoryClosure(out.CommandRoutes),
		requireNoLinkageDeadZones(out.DeadZones),
		validateBindingWitnessSelectorsAtRoot(".", bindings),
	)
	return writeMetrics(out, closeoutErr)
}

func validateBindingWitnessSelectorsAtRoot(root string, bindings bindingFile) error {
	if err := validateRequiredBindingWitnessSelectors(bindings); err != nil {
		return err
	}
	return validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings)
}

func validateRequiredBindingWitnessSelectors(bindings bindingFile) error {
	type inventoryKey struct {
		requirementID string
		scenarioID    string
	}
	required := map[inventoryKey][]string{
		{"REQ-PROOFKIT-PACKAGE-001", "proofkit.package-boundary.root-export-and-deep-import-denial"}: {"TestVerifyRootPackageRejectsEachForbiddenRootEntry"},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.launcher-profile-admission"}:         {"TestLauncherProfileAdmissionMatrix"},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.generated-command-field-inventory"}: {
			"TestGeneratedCommandInvocationProfileFieldInventory",
			"TestGeneratedCommandInvocationProfileRouteClosure",
		},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.generated-command-caller-preservation"}: {"TestBootstrapPreservesCallerDisplayCommandInGuidancePayload"},
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.cli-output-root-witnesses"}: {
			"TestAdoptionContractEnvelopeCLIABI",
			"TestRequirementAuthoringPlanOutputUsesVersionedRootShape",
			"TestSelfCheckOutputUsesExactRootShape",
			"TestStandaloneMultiVariantCommandsUseExactRootShapes",
		},
		{"REQ-PROOFKIT-PACKAGE-003", "proofkit.package-boundary.outside-consumer-artifact"}: {"TestExactTarballOnboardingTrace"},
		{"REQ-PROOFKIT-PACKAGE-004", "proofkit.package-boundary.ci-receipt-anchor"}: {
			"TestReceiptIDKeepsLocalAndCIIdentitiesDistinct",
			"TestRunInvokesEveryRequiredSelfHostingAdmissionBoundary",
		},
		{"REQ-PROOFKIT-PACKAGE-004", "proofkit.package-boundary.self-hosting-report-verdict"}:          {"TestRunProofkitVerdictCases"},
		{"REQ-PROOFKIT-PACKAGE-005", "proofkit.package-boundary.merge-critical-runtime-preconditions"}: {"TestCISourceQualityInstallsPythonBeforeLifecycleTests"},
		{"REQ-PROOFKIT-PACKAGE-006", "proofkit.package-boundary.python-wheel-candidate"}:               {"TestPythonArtifactRefsRejectEachWheelIdentityDefect"},
		{"REQ-PROOFKIT-PACKAGE-006", "proofkit.package-boundary.python-wheel-generated-continuation"}: {
			"TestExactDisplayedRouteOperandsRejectsWhitespaceAndExpansionMutants",
			"TestInstalledWheelContinuationUsesExactPythonModuleProfileWithoutNPM",
		},
		{"REQ-PROOFKIT-PACKAGE-007", "proofkit.package-boundary.package-public-docs-no-mutable-release-facts"}: {
			"TestVerifyNoStalePackageDocsRejectsMutableReleaseFactsInMarkdown",
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-abi-golden"}: {
			"TestAdoptionContractEnvelopeCLIABI",
			"TestRequiredInputCommandsRouteStructuralErrorsByMode",
			"TestRequirementAuthoringPlanOutputUsesVersionedRootShape",
			"TestRequirementBrowserOneShotCLIOutputVariants",
			"TestSelfCheckOutputUsesExactRootShape",
			"TestStandaloneMultiVariantCommandsUseExactRootShapes",
		},
		{"REQ-PROOFKIT-QUALITY-001", "proofkit.supply-chain-quality.release-attestation-wiring"}: {
			"TestReleaseWorkflowRetainsReleaseAssetAndPostCreateEvidenceClosure",
		},
		{"REQ-PROOFKIT-QUALITY-001", "proofkit.supply-chain-quality.retained-evidence-manifest"}: {
			"TestManifestRejectsUnboundAttestationAndSymlink",
			"TestManifestUsesDownloadableArtifactPaths",
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-contract-topology"}: {
			"TestCLIConditionModelClosesAdoptionOutputRoutes",
			"TestCommandDescriptorContractParityRejectsMutations",
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-output-witness-contract"}: {
			"TestRootDistinctOutputWitnessBindingsAreExact",
		},
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-output-schema-evolution"}: {
			"TestRequirementCoverageViewBreakingRootUsesVersionedOutputContract",
		},
		{"REQ-PROOFKIT-QUALITY-005", "proofkit.supply-chain-quality.codeql-permission-separation"}: {
			"TestSecurityScannerWorkflowsSeparateProviderPublicationPermissions",
		},
		{"REQ-PROOFKIT-QUALITY-006", "proofkit.supply-chain-quality.osv-permission-separation"}: {
			"TestOSVSourceScanFailsForEveryNonzeroScannerStatus",
			"TestSecurityScannerWorkflowsSeparateProviderPublicationPermissions",
		},
		{"REQ-PROOFKIT-QUALITY-007", "proofkit.supply-chain-quality.scorecard-permission-and-publication-inputs"}: {
			"TestScorecardPublicPublishDeclaresRequiredOutputInputs",
			"TestSecurityScannerWorkflowsSeparateProviderPublicationPermissions",
		},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.coverage-metrics"}: {"TestEachCommandRouteClosureConjunctHasIndependentFalsifier", "TestEachLinkageDeadZoneConjunctHasIndependentFalsifier"},
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.binding-selector-executability"}: {
			"TestBindingWitnessSelectorsAcceptUnnamedGoTestParameter",
			"TestBindingWitnessSelectorsRejectInvalidGoTestSignature",
			"TestBindingWitnessSelectorsRejectMissingSemanticOwner",
			"TestBindingWitnessSelectorsRejectNonTestAndBuildExcludedFiles",
			"TestBindingWitnessSelectorsRejectVacuousTestBody",
			"TestBindingWitnessSelectorsRequireExactCriticalInventories",
		},
		{"REQ-PROOFKIT-QUALITY-011", "proofkit.supply-chain-quality.ci-required-aggregate-exactness"}: {
			"TestCIRequiredAggregateRejectsExecutionOverrides",
			"TestCIRequiredAggregateRejectsNeutralizedScript",
			"TestCIRequiredAggregateRejectsPlatformSmokeSubstitution",
			"TestCIWorkflowDeclaresFailClosedRequiredAggregate",
		},
		{"REQ-PROOFKIT-QUALITY-013", "proofkit.supply-chain-quality.workflow-package-gate-oracle"}: {
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
		{"REQ-PROOFKIT-QUALITY-016", "proofkit.supply-chain-quality.release-platform-python-wheels"}: {
			"TestREADMEPlatformAndPythonProjection",
			"TestReleaseTargetsProjectExactPythonWheelMetadata",
			"TestVerifyWheelContentsRequiresExactWheelMetadata",
		},
		{"REQ-PROOFKIT-QUALITY-019", "proofkit.supply-chain-quality.installed-package-json-abi-smoke"}: {
			"TestExactTarballOnboardingTrace",
			"TestInstalledInvocationRequiresAuthoredOrderAndExactCommandToken",
			"TestInstalledREADMEFirstInputPreservesJSONExampleBytes",
			"TestInstalledREADMEFirstInputUsesBoundedLiteralShellWords",
			"TestLiteralShellWordsConsumesLongBackslashRun",
			"TestOnboardingTraceCoversEveryDiscoveredPresetAndREADMEInput",
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-manifest-json-abi-registry-evidence"}: {
			"TestNPMRegistryAuthorityFlowsFromAdmittedFileToPublishedChannel",
			"TestNPMRegistryPublicationRequiresTypedAuthorityEvidence",
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.npm-registry-authority-producer"}: {
			"TestRunBuildsCanonicalTypedRegistryEvidence",
			"TestRunRejectsRegistryPackageSetSubstitution",
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.npm-registry-workflow-delegation"}: {
			"TestReleaseWorkflowDelegatesNPMRegistryEvidenceToRepositoryOwner",
		},
		{"REQ-PROOFKIT-QUALITY-022", "proofkit.supply-chain-quality.browser-failure-diagnostics-retention"}: {
			"TestCIBrowserRuntimeRetainsFailureDiagnosticsWithoutPublishingProof",
		},
		{"REQ-PROOFKIT-QUALITY-023", "proofkit.supply-chain-quality.python-wheel-platform-byte-compatibility"}: {
			"TestMachOMinimumMacOSAcceptsLegacyVersionCommand",
			"TestMachOMinimumMacOSRejectsTruncatedBuildVersion",
			"TestVerifyWheelContentsAcceptsDarwinTagAtOrAboveMachOMinimum",
			"TestVerifyWheelContentsRejectsDarwinTagBelowMachOMinimum",
		},
		{"REQ-PROOFKIT-QUALITY-015", "proofkit.supply-chain-quality.release-closeout-completion-criteria"}: {
			"TestBuildInputFailsClosedForEachBlockingEvidenceClass",
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-change-record-projection"}: {
			"TestAdmitEnforcesVersionedChangeClass",
			"TestCurrentChangeRecordNamesReviewedSemanticChanges",
			"TestRenderStatesPreOneExactPinPolicy",
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.retained-evidence-artifact-topology"}: {
			"TestVerifyRejectsManifestAddressDrift",
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-closeout-change-record"}: {
			"TestBuildInputFailsClosedForEachBlockingEvidenceClass",
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-predecessor-lineage"}: {
			"TestRunNPMLineageUsesAdmittedRecordAndProviderIdentity",
			"TestValidateNPMReleaseLineage",
		},
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-predecessor-lineage-workflow"}: {
			"TestReleaseWorkflowCandidateEvidenceAllowsExistingNPMByteMatch",
		},
		{"REQ-PROOFKIT-QUALITY-025", "proofkit.supply-chain-quality.workflow-source-oracles"}: {
			"TestExistingReleasePathIsReadOnlyAndFailsOnDrift",
			"TestWorkflowClosedKeyAdmission",
			"TestWorkflowExternalActionsUseFullCommitSHAs",
		},
		{"REQ-PROOFKIT-SPEC-011", "proofkit.spec-proof-core.adoption-contract-envelope-cli-abi"}: {
			"TestAdoptionContractEnvelopeCLIABI",
		},
		{"REQ-PROOFKIT-SPEC-007", "proofkit.spec-proof-core.canonical-command-input-admission"}: {
			"TestRequiredInputCommandsRejectMalformedCallerRecords",
		},
		{"REQ-PROOFKIT-SPEC-007", "proofkit.spec-proof-core.canonical-input-admission"}: {
			"TestDecodeTypedJSONUsesStrictAdmission",
		},
		{"REQ-PROOFKIT-SPEC-013", "proofkit.spec-proof-core.receipt-trust-status-vocabulary-admission"}: {
			"TestBuildRejectsHigherRankThatWeakensMinimumTrustSemantics",
		},
		{"REQ-PROOFKIT-SPEC-021", "proofkit.spec-proof-core.requirement-browser-one-shot-cleanup"}: {
			"TestServeOneShotDoesNotReadCompletedDoneTwice",
			"TestServeOneShotReturnsCleanupFailuresWithoutWritingTerminalPacket",
			"TestServeOneShotWaitsForDoneBeforeWritingTerminalPacket",
		},
		{"REQ-PROOFKIT-SPEC-006", "proofkit.spec-proof-core.test-inventory-and-coverage-view"}: {
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
		{"REQ-PROOFKIT-SPEC-006", "proofkit.spec-proof-core.declared-route-mapping-without-assurance"}: {
			"TestBuildJSONMissingSelectorRemainsMappingOnly",
		},
		{"REQ-PROOFKIT-SPEC-012", "proofkit.spec-proof-core.requirement-authoring-ref-provenance"}: {
			"TestBuildPreservesDigestBoundAuthoringRefIdentity",
		},
		{"REQ-PROOFKIT-RETIRE-006", "proofkit.consumer-infra-retirement.migration-parity-admission"}: {
			"TestBuildProjectsEveryCallerDeclaredStatusAndSummaryField",
		},
	}
	requiredPaths := map[inventoryKey]string{
		{"REQ-PROOFKIT-PACKAGE-001", "proofkit.package-boundary.root-export-and-deep-import-denial"}:              "internal/tools/packageverify/main_test.go",
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.launcher-profile-admission"}:                      "internal/kernel/cliexec/cliexec_test.go",
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.generated-command-field-inventory"}:               "internal/app/invocation_profile_test.go",
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.generated-command-caller-preservation"}:           "internal/command/gradualadoption/gradualadoption_test.go",
		{"REQ-PROOFKIT-PACKAGE-002", "proofkit.package-boundary.cli-output-root-witnesses"}:                       "internal/app/cli_abi_test.go",
		{"REQ-PROOFKIT-PACKAGE-003", "proofkit.package-boundary.outside-consumer-artifact"}:                       "internal/tools/packageverify/main_test.go",
		{"REQ-PROOFKIT-PACKAGE-004", "proofkit.package-boundary.ci-receipt-anchor"}:                               "scripts/validate-self-hosting-receipts_test.go",
		{"REQ-PROOFKIT-PACKAGE-004", "proofkit.package-boundary.self-hosting-report-verdict"}:                     "scripts/validate-self-hosting-receipts_test.go",
		{"REQ-PROOFKIT-PACKAGE-005", "proofkit.package-boundary.merge-critical-runtime-preconditions"}:            "scripts/workflow_runtime_preconditions_test.go",
		{"REQ-PROOFKIT-PACKAGE-006", "proofkit.package-boundary.python-wheel-candidate"}:                          "scripts/validate-self-hosting-receipts_test.go",
		{"REQ-PROOFKIT-PACKAGE-006", "proofkit.package-boundary.python-wheel-generated-continuation"}:             "internal/tools/pythonpackage/continuation_test.go",
		{"REQ-PROOFKIT-PACKAGE-007", "proofkit.package-boundary.package-public-docs-no-mutable-release-facts"}:    "internal/tools/packageverify/main_test.go",
		{"REQ-PROOFKIT-QUALITY-001", "proofkit.supply-chain-quality.release-attestation-wiring"}:                  "scripts/validate-self-hosting-receipts_test.go",
		{"REQ-PROOFKIT-QUALITY-001", "proofkit.supply-chain-quality.retained-evidence-manifest"}:                  "internal/tools/retainedevidence/manifest_test.go",
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-abi-golden"}:                              "internal/app/cli_abi_test.go",
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-contract-topology"}:                       "internal/app/cli_contract_test.go",
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-output-witness-contract"}:                 "internal/app/cli_output_witness_contract_test.go",
		{"REQ-PROOFKIT-QUALITY-004", "proofkit.supply-chain-quality.cli-output-schema-evolution"}:                 "internal/app/cli_contract_test.go",
		{"REQ-PROOFKIT-QUALITY-005", "proofkit.supply-chain-quality.codeql-permission-separation"}:                "scripts/workflow_security_scanner_oracles_test.go",
		{"REQ-PROOFKIT-QUALITY-006", "proofkit.supply-chain-quality.osv-permission-separation"}:                   "scripts/workflow_security_scanner_oracles_test.go",
		{"REQ-PROOFKIT-QUALITY-007", "proofkit.supply-chain-quality.scorecard-permission-and-publication-inputs"}: "scripts/workflow_security_scanner_oracles_test.go",
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.binding-selector-executability"}:              "internal/tools/coveragemetrics/main_test.go",
		{"REQ-PROOFKIT-QUALITY-010", "proofkit.supply-chain-quality.coverage-metrics"}:                            "internal/tools/coveragemetrics/main_test.go",
		{"REQ-PROOFKIT-QUALITY-011", "proofkit.supply-chain-quality.ci-required-aggregate-exactness"}:             "scripts/workflow_package_gate_oracle_test.go",
		{"REQ-PROOFKIT-QUALITY-013", "proofkit.supply-chain-quality.workflow-package-gate-oracle"}:                "scripts/workflow_package_gate_oracle_test.go",
		{"REQ-PROOFKIT-QUALITY-016", "proofkit.supply-chain-quality.release-platform-python-wheels"}:              "internal/tools/pythonpackage/metadata_test.go",
		{"REQ-PROOFKIT-QUALITY-019", "proofkit.supply-chain-quality.installed-package-json-abi-smoke"}:            "internal/tools/packageverify/main_test.go",
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-manifest-json-abi-registry-evidence"}: "internal/tools/releasemanifest/main_test.go",
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.npm-registry-authority-producer"}:             "internal/tools/npmregistry/main_test.go",
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.npm-registry-workflow-delegation"}:            "scripts/validate-self-hosting-receipts_test.go",
		{"REQ-PROOFKIT-QUALITY-022", "proofkit.supply-chain-quality.browser-failure-diagnostics-retention"}:       "scripts/workflow_browser_runtime_oracle_test.go",
		{"REQ-PROOFKIT-QUALITY-023", "proofkit.supply-chain-quality.python-wheel-platform-byte-compatibility"}:    "internal/tools/pythonpackage/metadata_test.go",
		{"REQ-PROOFKIT-QUALITY-015", "proofkit.supply-chain-quality.release-closeout-completion-criteria"}:        "internal/tools/releasecloseoutinput/main_test.go",
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-change-record-projection"}:            "internal/tools/releasechange/record_test.go",
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.retained-evidence-artifact-topology"}:         "internal/tools/retainedevidence/manifest_test.go",
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-closeout-change-record"}:              "internal/tools/releasecloseoutinput/main_test.go",
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-predecessor-lineage"}:                 "internal/tools/releasepreflight/main_test.go",
		{"REQ-PROOFKIT-QUALITY-024", "proofkit.supply-chain-quality.release-predecessor-lineage-workflow"}:        "scripts/validate-self-hosting-receipts_test.go",
		{"REQ-PROOFKIT-QUALITY-025", "proofkit.supply-chain-quality.workflow-source-oracles"}:                     "scripts/workflow_source_oracles_test.go",
		{"REQ-PROOFKIT-RETIRE-006", "proofkit.consumer-infra-retirement.migration-parity-admission"}:              "internal/command/migrationparityadmission/migrationparityadmission_test.go",
		{"REQ-PROOFKIT-SPEC-011", "proofkit.spec-proof-core.adoption-contract-envelope-cli-abi"}:                  "internal/app/cli_abi_test.go",
		{"REQ-PROOFKIT-SPEC-007", "proofkit.spec-proof-core.canonical-command-input-admission"}:                   "internal/app/command_coverage_test.go",
		{"REQ-PROOFKIT-SPEC-007", "proofkit.spec-proof-core.canonical-input-admission"}:                           "internal/kernel/admission/json_test.go",
		{"REQ-PROOFKIT-SPEC-013", "proofkit.spec-proof-core.receipt-trust-status-vocabulary-admission"}:           "internal/command/receipttrustclass/receipt_trust_class_test.go",
		{"REQ-PROOFKIT-SPEC-021", "proofkit.spec-proof-core.requirement-browser-one-shot-cleanup"}:                "internal/command/requirementbrowser/server_test.go",
		{"REQ-PROOFKIT-SPEC-006", "proofkit.spec-proof-core.test-inventory-and-coverage-view"}:                    "internal/command/requirementcoverageview/output_closure_test.go",
		{"REQ-PROOFKIT-SPEC-006", "proofkit.spec-proof-core.declared-route-mapping-without-assurance"}:            "internal/command/requirementcoverageview/requirementcoverageview_test.go",
		{"REQ-PROOFKIT-SPEC-012", "proofkit.spec-proof-core.requirement-authoring-ref-provenance"}:                "internal/command/requirementauthoringplan/requirement_authoring_plan_test.go",
	}
	if len(requiredPaths) != len(required) {
		return fmt.Errorf("required selector path inventory=%d, selector inventory=%d", len(requiredPaths), len(required))
	}
	seenRequired := map[inventoryKey]struct{}{}
	for _, binding := range bindings.Bindings {
		key := inventoryKey{requirementID: binding.RequirementID, scenarioID: binding.ScenarioID}
		want, isRequired := required[key]
		if !isRequired {
			continue
		}
		wantPath, hasRequiredPath := requiredPaths[key]
		if !hasRequiredPath {
			return fmt.Errorf("binding %s has selectors but no exact witness path inventory", binding.ScenarioID)
		}
		if binding.WitnessPath != wantPath {
			return fmt.Errorf("binding %s witness path=%q, want exact %q", binding.ScenarioID, binding.WitnessPath, wantPath)
		}
		seenRequired[key] = struct{}{}
		got := make([]string, 0, len(binding.WitnessSelectors))
		for _, selector := range binding.WitnessSelectors {
			got = append(got, selector.Selector)
		}
		sort.Strings(got)
		if !equalStrings(got, want) {
			return fmt.Errorf("binding %s witness selectors=%v, want %v", binding.ScenarioID, got, want)
		}
	}
	for key := range required {
		if _, ok := requiredPaths[key]; !ok {
			return fmt.Errorf("required exact witness path is missing: %s/%s", key.requirementID, key.scenarioID)
		}
		if _, ok := seenRequired[key]; !ok {
			return fmt.Errorf("required independent-falsifier binding is missing: %s/%s", key.requirementID, key.scenarioID)
		}
	}
	return nil
}

func validateBindingWitnessSelectorExecutabilityAtRoot(root string, bindings bindingFile) error {
	activeWitnessPackages := map[string]map[string]struct{}{}
	packageFunctionScopes := map[string]map[string]*ast.FuncDecl{}
	for _, binding := range bindings.Bindings {
		if len(binding.WitnessSelectors) == 0 {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(binding.WitnessPath))
		source, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse binding witness %s: %w", binding.WitnessPath, err)
		}
		witnessFunctions := map[string]*ast.FuncDecl{}
		for _, declaration := range source.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil {
				witnessFunctions[function.Name.Name] = function
			}
		}
		testingAliases, dotImportedTesting := importedTestingNames(source)
		packagePath := "./" + filepath.ToSlash(filepath.Dir(binding.WitnessPath))
		for _, selector := range binding.WitnessSelectors {
			function, ok := witnessFunctions[selector.Selector]
			if !ok {
				return fmt.Errorf("binding %s selector %s is missing from %s", binding.ScenarioID, selector.Selector, binding.WitnessPath)
			}
			if !validGoTestFunction(function, testingAliases, dotImportedTesting) {
				return fmt.Errorf("binding %s selector %s is not a valid Go test function", binding.ScenarioID, selector.Selector)
			}
			expectedCommand := fmt.Sprintf("go test %s -run '^%s$'", packagePath, selector.Selector)
			if selector.Command != expectedCommand {
				return fmt.Errorf("binding %s selector command=%q, want %q", binding.ScenarioID, selector.Command, expectedCommand)
			}
		}
		if !strings.HasSuffix(binding.WitnessPath, "_test.go") {
			return fmt.Errorf("binding %s witness %s must be an active _test.go file", binding.ScenarioID, binding.WitnessPath)
		}
		activeFiles, checked := activeWitnessPackages[packagePath]
		if !checked {
			activeFiles, err = activeGoTestFiles(root, packagePath)
			if err != nil {
				return fmt.Errorf("discover binding witness %s: %w", binding.WitnessPath, err)
			}
			activeWitnessPackages[packagePath] = activeFiles
		}
		witnessAbsolute, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(binding.WitnessPath)))
		if err != nil {
			return err
		}
		if _, active := activeFiles[filepath.Clean(witnessAbsolute)]; !active {
			return fmt.Errorf("binding %s witness %s is not active for the current Go build", binding.ScenarioID, binding.WitnessPath)
		}
		scopeKey := packagePath + ":" + source.Name.Name
		functionScope, scoped := packageFunctionScopes[scopeKey]
		if !scoped {
			functionScope, err = activePackageFunctions(activeFiles, source.Name.Name)
			if err != nil {
				return fmt.Errorf("parse active package functions for %s: %w", binding.WitnessPath, err)
			}
			packageFunctionScopes[scopeKey] = functionScope
		}
		for _, selector := range binding.WitnessSelectors {
			function := witnessFunctions[selector.Selector]
			if gotestsource.HasSkip(function) {
				return fmt.Errorf("binding %s selector %s contains t.Skip and cannot serve as an always-executable witness", binding.ScenarioID, selector.Selector)
			}
			if !gotestsource.HasFailureCapableAssertionCandidate(function, functionScope) {
				return fmt.Errorf("binding %s selector %s has no failure-capable assertion candidate", binding.ScenarioID, selector.Selector)
			}
		}
	}
	return nil
}

func activePackageFunctions(activeFiles map[string]struct{}, packageName string) (map[string]*ast.FuncDecl, error) {
	paths := make([]string, 0, len(activeFiles))
	for path := range activeFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	functions := map[string]*ast.FuncDecl{}
	for _, path := range paths {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return nil, err
		}
		if file.Name.Name != packageName {
			continue
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil {
				functions[function.Name.Name] = function
			}
		}
	}
	return functions, nil
}

func activeGoTestFiles(root, packagePath string) (map[string]struct{}, error) {
	command := exec.Command("go", "list", "-json", packagePath)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go list %s: %w: %s", packagePath, err, strings.TrimSpace(string(output)))
	}
	var listed struct {
		Dir          string
		TestGoFiles  []string
		XTestGoFiles []string
	}
	if err := json.Unmarshal(output, &listed); err != nil {
		return nil, fmt.Errorf("decode go list %s: %w", packagePath, err)
	}
	activeFiles := map[string]struct{}{}
	for _, file := range append(listed.TestGoFiles, listed.XTestGoFiles...) {
		activeAbsolute, err := filepath.Abs(filepath.Join(listed.Dir, file))
		if err != nil {
			return nil, err
		}
		activeFiles[filepath.Clean(activeAbsolute)] = struct{}{}
	}
	return activeFiles, nil
}

func importedTestingNames(source *ast.File) (map[string]struct{}, bool) {
	aliases := map[string]struct{}{}
	dotImported := false
	for _, specification := range source.Imports {
		path, err := strconv.Unquote(specification.Path.Value)
		if err != nil || path != "testing" {
			continue
		}
		switch {
		case specification.Name == nil:
			aliases["testing"] = struct{}{}
		case specification.Name.Name == ".":
			dotImported = true
		case specification.Name.Name != "_":
			aliases[specification.Name.Name] = struct{}{}
		}
	}
	return aliases, dotImported
}

func validGoTestFunction(function *ast.FuncDecl, testingAliases map[string]struct{}, dotImportedTesting bool) bool {
	if !validGoTestName(function.Name.Name) ||
		function.Type.TypeParams != nil ||
		function.Type.Results != nil && len(function.Type.Results.List) != 0 ||
		function.Type.Params == nil || len(function.Type.Params.List) != 1 {
		return false
	}
	parameter := function.Type.Params.List[0]
	if len(parameter.Names) > 1 {
		return false
	}
	pointer, ok := parameter.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if identifier, ok := pointer.X.(*ast.Ident); ok {
		return dotImportedTesting && identifier.Name == "T"
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "T" {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	_, ok = testingAliases[identifier.Name]
	return ok
}

func validGoTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") {
		return false
	}
	suffix := strings.TrimPrefix(name, "Test")
	if suffix == "" {
		return true
	}
	first, _ := utf8.DecodeRuneInString(suffix)
	return !unicode.IsLower(first)
}

func equalStrings(left, right []string) bool {
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func bindCurrentSourceProvenance(out *metrics) error {
	revision, sourceDigest, err := packageartifactrecord.SourceSnapshot(".")
	if err != nil {
		return fmt.Errorf("bind coverage metrics source snapshot: %w", err)
	}
	out.Provenance = coverageProvenance{
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		ProducerCommandID:    "proofkit.coverage-metrics",
		SourceRevision:       revision,
		SourceSnapshotDigest: sourceDigest,
	}
	return nil
}

func writeMetrics(out metrics, routeErr error) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	content, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, append(content, '\n'), 0o644); err != nil {
		return err
	}
	if routeErr != nil {
		return routeErr
	}
	fmt.Printf("coverage metrics: requirements=%d bound=%d scenarios=%d commands=%d\n",
		out.Requirements.TotalRecords,
		out.ProofBindings.BoundRequirementCount,
		out.ProofBindings.ScenarioCount,
		out.CLIContract.CommandCount,
	)
	return nil
}

func readRequirements() ([]requirementRecord, error) {
	paths, err := filepath.Glob("docs/specs/*/requirements.v1.json")
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no requirement source files found")
	}
	sort.Strings(paths)
	out := []requirementRecord{}
	for _, path := range paths {
		raw, err := readAnyJSON(path)
		if err != nil {
			return nil, err
		}
		result, err := requirementsourceadmission.Evaluate(raw)
		if err != nil {
			return nil, fmt.Errorf("%s requirement source admission failed: %w", path, err)
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("%s requirement source admission failed: %v", path, result.Failures)
		}
		if filepath.ToSlash(path) != result.Source.RequirementsPath {
			return nil, fmt.Errorf("%s requirement source requirementsPath must match the source file path", path)
		}
		for _, requirement := range result.Source.Requirements {
			out = append(out, requirementRecord{
				ClaimLevel:    requirement.ClaimLevel,
				Lifecycle:     lifecycle{State: requirement.Lifecycle.State},
				RequirementID: requirement.RequirementID,
			})
		}
	}
	return out, nil
}

func readAnyJSON(path string) (any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	out, err := admission.DecodeJSON(file, 16<<20)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return out, nil
}

func readJSON[T any](path string) (T, error) {
	var out T
	file, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer file.Close()
	out, err = admission.DecodeTypedJSON[T](file, 16<<20)
	if err != nil {
		return out, fmt.Errorf("decode %s: %w", path, err)
	}
	return out, nil
}

func buildMetrics(requirements []requirementRecord, bindings bindingFile, witnesses witnessPlan, contract cliContract, commandInventory testevidenceinventory.Inventory) metrics {
	requirementIDs := map[string]struct{}{}
	active := 0
	blocking := 0
	for _, requirement := range requirements {
		requirementIDs[requirement.RequirementID] = struct{}{}
		if requirement.Lifecycle.State == "active" {
			active++
		}
		if requirement.ClaimLevel == "blocking" {
			blocking++
		}
	}
	boundIDs := map[string]struct{}{}
	witnessBacked := map[string]struct{}{}
	bindingWithoutRequirement := []string{}
	for _, binding := range bindings.Requirements {
		boundIDs[binding.RequirementID] = struct{}{}
		if _, ok := requirementIDs[binding.RequirementID]; !ok {
			bindingWithoutRequirement = append(bindingWithoutRequirement, binding.RequirementID)
		}
		if binding.ProofState == "witness_backed" {
			witnessBacked[binding.RequirementID] = struct{}{}
		}
	}
	requirementWithoutBinding := []string{}
	for id := range requirementIDs {
		if _, ok := boundIDs[id]; !ok {
			requirementWithoutBinding = append(requirementWithoutBinding, id)
		}
	}
	commandIDs := map[string]struct{}{}
	for _, command := range witnesses.Commands {
		commandIDs[command.ID] = struct{}{}
	}
	scenarioWithoutCommand := []string{}
	scenarioWithoutRequirement := []string{}
	for _, scenario := range bindings.Bindings {
		if _, ok := requirementIDs[scenario.RequirementID]; !ok {
			scenarioWithoutRequirement = append(scenarioWithoutRequirement, scenario.ScenarioID)
		}
		for _, commandID := range scenario.CommandIDs {
			if _, ok := commandIDs[commandID]; !ok {
				scenarioWithoutCommand = append(scenarioWithoutCommand, scenario.ScenarioID)
				break
			}
		}
	}
	sort.Strings(bindingWithoutRequirement)
	sort.Strings(requirementWithoutBinding)
	sort.Strings(scenarioWithoutCommand)
	sort.Strings(scenarioWithoutRequirement)
	contractCommands := cliContractCommandNames(contract)
	commandRoutes := buildCommandRouteMetrics(contract, app.CommandCoverageSummaries(), commandInventory)
	return metrics{
		ArtifactKind:  "proofkit.coverage-metrics.v1",
		SchemaVersion: 1,
		Requirements: requirementMetrics{
			Active:       active,
			Blocking:     blocking,
			SourceFiles:  requirementSourceCount(),
			TotalRecords: len(requirements),
		},
		ProofBindings: proofBindingMetrics{
			BoundRequirementCount:         len(boundIDs),
			ScenarioCount:                 len(bindings.Bindings),
			WitnessBackedRequirementCount: len(witnessBacked),
		},
		WitnessPlan:   witnessPlanMetrics{CommandCount: len(commandIDs)},
		CLIContract:   cliContractMetrics{CommandCount: len(contractCommands), Commands: contractCommands},
		CommandRoutes: commandRoutes,
		DeadZones: deadZoneMetrics{
			BindingWithoutRequirementIDs:  bindingWithoutRequirement,
			RequirementWithoutBindingIDs:  requirementWithoutBinding,
			ScenarioWithoutCommandIDs:     scenarioWithoutCommand,
			ScenarioWithoutRequirementIDs: scenarioWithoutRequirement,
		},
		NonClaims: []string{
			"Coverage metrics report explicit requirement, binding, witness, and CLI inventory linkage only.",
			"Coverage metrics classify static command route metadata as proof_route_candidate; route prose, source markers, test existence, and failure-capable AST nodes do not become execution-backed semantic evidence.",
			"Coverage metrics do not execute command route candidates or observe a concrete falsification event.",
			"Coverage metrics do not claim line coverage, semantic correctness, command execution, receipt freshness, or merge satisfaction.",
		},
	}
}

func cliContractCommandNames(contract cliContract) []string {
	commands := make([]string, 0, len(contract.Commands))
	for _, command := range contract.Commands {
		commands = append(commands, command.Command)
	}
	sort.Strings(commands)
	return commands
}

func readCommandCoverageInventory() (testevidenceinventory.Inventory, error) {
	raw, err := commandCoverageInventoryInput()
	if err != nil {
		return testevidenceinventory.Inventory{}, fmt.Errorf("command coverage route inventory failed: %w", err)
	}
	return readCommandCoverageInventoryFrom(raw)
}

func readCommandCoverageInventoryFrom(raw any) (testevidenceinventory.Inventory, error) {
	result, err := testevidenceinventory.Evaluate(raw)
	if err != nil {
		return testevidenceinventory.Inventory{}, fmt.Errorf("command coverage inventory admission failed: %w", err)
	}
	if result.ExitCode != 0 {
		return testevidenceinventory.Inventory{}, fmt.Errorf("command coverage inventory admission failed: %v", result.Failures)
	}
	return result.Inventory, nil
}

func buildCommandRouteMetrics(contract cliContract, summaries []app.CommandCoverageSummary, inventory testevidenceinventory.Inventory) commandRouteMetrics {
	missingCandidates := []string{}
	missingDeclaredSemanticRoutes := []string{}
	contractRefs := map[string]string{}
	knownRefs := map[string]struct{}{}
	candidateRefs := map[string]struct{}{}
	declaredSemanticRouteRefs := map[string]struct{}{}
	routeOnlyCount := 0
	candidateEntryCount := 0
	declaredSemanticRouteEntryCount := 0
	for _, command := range contract.Commands {
		contractRefs[app.CommandCoverageCommandRef(command.Command)] = command.Command
	}
	for _, summary := range summaries {
		knownRefs[summary.CommandRef] = struct{}{}
	}
	for _, entry := range inventory.Entries {
		switch entry.EvidenceClass {
		case testevidenceinventory.EvidenceClassDeclaredSemanticFalsifierRoute:
			declaredSemanticRouteEntryCount++
			for _, commandRef := range entry.CommandRefs {
				declaredSemanticRouteRefs[commandRef] = struct{}{}
			}
		case testevidenceinventory.EvidenceClassProofRouteCandidate:
			candidateEntryCount++
			for _, commandRef := range entry.CommandRefs {
				candidateRefs[commandRef] = struct{}{}
			}
		case "routing_smoke_nonclaim":
			routeOnlyCount++
		}
	}
	unknownDeclaredSemanticRouteRefs := []string{}
	for ref := range declaredSemanticRouteRefs {
		if _, ok := knownRefs[ref]; !ok {
			unknownDeclaredSemanticRouteRefs = append(unknownDeclaredSemanticRouteRefs, ref)
		}
	}
	unknownCandidateRefs := []string{}
	for ref := range candidateRefs {
		if _, ok := knownRefs[ref]; !ok {
			unknownCandidateRefs = append(unknownCandidateRefs, ref)
		}
	}
	contractOnly := []string{}
	for ref, command := range contractRefs {
		if _, ok := knownRefs[ref]; !ok {
			contractOnly = append(contractOnly, command)
		}
	}
	routeOnly := []string{}
	for _, summary := range summaries {
		if _, ok := contractRefs[summary.CommandRef]; !ok {
			routeOnly = append(routeOnly, summary.Command)
		}
	}
	sort.Strings(contractOnly)
	sort.Strings(routeOnly)
	sort.Strings(unknownCandidateRefs)
	sort.Strings(unknownDeclaredSemanticRouteRefs)
	out := commandRouteMetrics{
		AdmittedInventoryEntryCount:                 len(inventory.Entries),
		CommandCount:                                len(summaries),
		ContractOnlyCommands:                        contractOnly,
		ContractOnlyCommandCount:                    len(contractOnly),
		RouteOnlyCommands:                           routeOnly,
		RouteOnlyCommandCount:                       len(routeOnly),
		RouteSmokeCount:                             routeOnlyCount,
		ProofRouteCandidateInventoryEntryCount:      candidateEntryCount,
		DeclaredSemanticFalsifierRouteEntryCount:    declaredSemanticRouteEntryCount,
		UnknownProofRouteCandidateRefs:              unknownCandidateRefs,
		UnknownProofRouteCandidateRefCount:          len(unknownCandidateRefs),
		UnknownDeclaredSemanticRouteCommandRefs:     unknownDeclaredSemanticRouteRefs,
		UnknownDeclaredSemanticRouteCommandRefCount: len(unknownDeclaredSemanticRouteRefs),
	}
	for _, summary := range summaries {
		out.Commands = append(out.Commands, summary.Command)
		out.RouteCount += summary.RouteCount
		out.ProofRouteCandidateRouteCount += summary.ProofRouteCandidateCount
		if _, ok := candidateRefs[summary.CommandRef]; !ok {
			missingCandidates = append(missingCandidates, summary.Command)
		}
		if _, ok := declaredSemanticRouteRefs[summary.CommandRef]; !ok {
			missingDeclaredSemanticRoutes = append(missingDeclaredSemanticRoutes, summary.Command)
		}
	}
	sort.Strings(out.Commands)
	sort.Strings(missingCandidates)
	sort.Strings(missingDeclaredSemanticRoutes)
	out.CommandsWithoutProofRouteCandidate = missingCandidates
	out.CommandWithoutProofRouteCandidateCount = len(missingCandidates)
	out.CommandsWithoutDeclaredSemanticFalsifierRoute = missingDeclaredSemanticRoutes
	out.CommandWithoutDeclaredSemanticFalsifierRouteCount = len(missingDeclaredSemanticRoutes)
	return out
}

func requireCommandRouteInventoryClosure(metrics commandRouteMetrics) error {
	if len(metrics.CommandsWithoutProofRouteCandidate) == 0 &&
		len(metrics.UnknownProofRouteCandidateRefs) == 0 &&
		len(metrics.UnknownDeclaredSemanticRouteCommandRefs) == 0 &&
		len(metrics.ContractOnlyCommands) == 0 &&
		len(metrics.RouteOnlyCommands) == 0 {
		return nil
	}
	return fmt.Errorf("command proof-route inventory defects: missingCandidates=%v unknownCandidateRefs=%v unknownDeclaredSemanticRouteRefs=%v contractOnly=%v routeOnly=%v",
		metrics.CommandsWithoutProofRouteCandidate,
		metrics.UnknownProofRouteCandidateRefs,
		metrics.UnknownDeclaredSemanticRouteCommandRefs,
		metrics.ContractOnlyCommands,
		metrics.RouteOnlyCommands,
	)
}

func requireNoLinkageDeadZones(metrics deadZoneMetrics) error {
	if len(metrics.BindingWithoutRequirementIDs) == 0 &&
		len(metrics.RequirementWithoutBindingIDs) == 0 &&
		len(metrics.ScenarioWithoutCommandIDs) == 0 &&
		len(metrics.ScenarioWithoutRequirementIDs) == 0 {
		return nil
	}
	return fmt.Errorf("coverage metrics contain requirement/proof linkage dead zones: bindingWithoutRequirement=%v requirementWithoutBinding=%v scenarioWithoutCommand=%v scenarioWithoutRequirement=%v",
		metrics.BindingWithoutRequirementIDs,
		metrics.RequirementWithoutBindingIDs,
		metrics.ScenarioWithoutCommandIDs,
		metrics.ScenarioWithoutRequirementIDs,
	)
}

func requirementSourceCount() int {
	paths, err := filepath.Glob("docs/specs/*/requirements.v1.json")
	if err != nil {
		return 0
	}
	return len(paths)
}
